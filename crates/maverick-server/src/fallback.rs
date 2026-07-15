use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{CONNECTION, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use maverick_core::config::FallbackConfig;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_PROXY_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_STATIC_RESPONSE_BYTES: u64 = 1024 * 1024;
const DEFAULT_REVERSE_PROXY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub enum FallbackHandler {
    Static(StaticFallback),
    ReverseProxy(ReverseProxyFallback),
}

impl FallbackHandler {
    pub fn from_config(config: &FallbackConfig) -> Self {
        match config {
            FallbackConfig::Static { .. } => Self::Static(StaticFallback::from_config(config)),
            FallbackConfig::ReverseProxy { upstream } => Self::ReverseProxy(ReverseProxyFallback {
                upstream: upstream.clone(),
                timeout: DEFAULT_REVERSE_PROXY_TIMEOUT,
            }),
        }
    }

    pub async fn response_for(
        &self,
        method: &Method,
        path_and_query: &str,
    ) -> Result<Response<Bytes>> {
        self.response_for_with_body(method, path_and_query, &HeaderMap::new(), Bytes::new())
            .await
    }

    pub async fn response_for_with_body(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        request_body: Bytes,
    ) -> Result<Response<Bytes>> {
        match self {
            Self::Static(fallback) => fallback.response_for_path(path_and_query).await,
            Self::ReverseProxy(fallback) => {
                fallback
                    .response_for(method, path_and_query, headers, request_body)
                    .await
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct StaticFallback {
    static_dir: PathBuf,
    index: String,
}

impl StaticFallback {
    fn from_config(config: &FallbackConfig) -> Self {
        match config {
            FallbackConfig::Static { static_dir, index } => Self {
                static_dir: static_dir.clone(),
                index: index.clone(),
            },
            FallbackConfig::ReverseProxy { .. } => unreachable!("not a static fallback config"),
        }
    }

    pub async fn response_for_path(&self, path: &str) -> Result<Response<Bytes>> {
        let file_path = self.resolve_path(path);
        let root = match fs::canonicalize(&self.static_dir).await {
            Ok(root) => root,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return not_found_response();
            }
            Err(_) => return internal_error_response(),
        };
        let file_path = match fs::canonicalize(&file_path).await {
            Ok(path) => path,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return not_found_response();
            }
            Err(_) => return internal_error_response(),
        };
        if !file_path.starts_with(&root) {
            return not_found_response();
        }
        let metadata = match fs::metadata(&file_path).await {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return not_found_response();
            }
            Err(_) => return internal_error_response(),
        };
        if !metadata.is_file() {
            return not_found_response();
        }
        if metadata.len() > MAX_STATIC_RESPONSE_BYTES {
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("content-type", "text/plain; charset=utf-8")
                .body(Bytes::from_static(b"Payload Too Large"))?);
        }
        let bytes = match fs::read(&file_path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return not_found_response();
            }
            Err(_) => return internal_error_response(),
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type_for(&file_path))
            .body(Bytes::from(bytes))?)
    }

    fn resolve_path(&self, request_path: &str) -> PathBuf {
        let request_path = request_path.split('?').next().unwrap_or(request_path);
        let relative = request_path.trim_start_matches('/');
        let relative = if relative.is_empty() {
            self.index.as_str()
        } else {
            relative
        };
        let mut safe = PathBuf::new();
        for component in Path::new(relative).components() {
            if let Component::Normal(part) = component {
                safe.push(part);
            }
        }
        self.static_dir.join(safe)
    }
}

fn not_found_response() -> Result<Response<Bytes>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Bytes::from_static(b"Not Found"))?)
}

fn internal_error_response() -> Result<Response<Bytes>> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Bytes::from_static(b"Internal Server Error"))?)
}

#[derive(Clone, Debug)]
pub struct ReverseProxyFallback {
    upstream: String,
    timeout: Duration,
}

impl ReverseProxyFallback {
    async fn response_for(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        request_body: Bytes,
    ) -> Result<Response<Bytes>> {
        let upstream: Uri = self
            .upstream
            .parse()
            .context("parse reverse proxy upstream")?;
        if upstream.scheme_str() != Some("http") {
            bail!("only http reverse proxy upstreams are supported in v1.1");
        }
        let authority = upstream.authority().context("upstream missing authority")?;
        let host_header = authority.as_str();
        let upstream_base_path = upstream.path().trim_end_matches('/');
        let path_and_query = if path_and_query.is_empty() {
            "/"
        } else {
            path_and_query
        };
        let request_target = if upstream_base_path.is_empty() {
            path_and_query.to_owned()
        } else if path_and_query == "/" {
            upstream_base_path.to_owned()
        } else {
            format!("{upstream_base_path}{path_and_query}")
        };
        let stream = timeout(
            self.timeout,
            TcpStream::connect((authority.host(), authority.port_u16().unwrap_or(80))),
        )
        .await
        .context("reverse proxy upstream connect timed out")??;
        let mut builder = http1::Builder::new();
        builder.max_headers(128).max_buf_size(64 * 1024);
        let (mut sender, connection) = timeout(
            self.timeout,
            builder.handshake::<_, Full<Bytes>>(TokioIo::new(stream)),
        )
        .await
        .context("reverse proxy HTTP handshake timed out")??;
        let connection_task = tokio::spawn(connection);

        let result = async {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(request_target)
                .body(Full::new(request_body))?;
            request
                .headers_mut()
                .insert(HOST, HeaderValue::from_str(host_header)?);
            request
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
            let connection_headers = connection_header_names(headers);
            for (name, value) in headers {
                if !is_forwardable_request_header(name, &connection_headers) {
                    continue;
                }
                request.headers_mut().append(name, value.clone());
            }

            let response = timeout(self.timeout, sender.send_request(request))
                .await
                .context("reverse proxy upstream response timed out")??;
            let (mut parts, body) = response.into_parts();
            let collected = timeout(
                self.timeout,
                Limited::new(body, MAX_PROXY_RESPONSE_BYTES).collect(),
            )
            .await
            .context("reverse proxy upstream body timed out")?
            .map_err(|error| anyhow::anyhow!("reverse proxy upstream body failed: {error}"))?;
            strip_hop_by_hop_headers(&mut parts.headers);
            Ok(Response::from_parts(parts, collected.to_bytes()))
        }
        .await;
        connection_task.abort();
        result
    }
}

fn is_forwardable_request_header(name: &HeaderName, connection_headers: &[HeaderName]) -> bool {
    let name = name.as_str();
    !name.eq_ignore_ascii_case("host")
        && !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("transfer-encoding")
        && !is_hop_by_hop_header(name)
        && !name.starts_with(':')
        && !connection_headers
            .iter()
            .any(|connection_name| connection_name.as_str().eq_ignore_ascii_case(name))
}

fn connection_header_names(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_headers = connection_header_names(headers);
    let removed = headers
        .keys()
        .filter(|name| {
            is_hop_by_hop_header(name.as_str())
                || connection_headers
                    .iter()
                    .any(|connection_name| connection_name == *name)
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in removed {
        headers.remove(name);
    }
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn fallback_static_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.html"), b"hello")
            .await
            .unwrap();
        let fallback = StaticFallback {
            static_dir: dir.path().to_path_buf(),
            index: "index.html".into(),
        };
        let response = fallback.response_for_path("/").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn fallback_unknown_path() {
        let dir = tempdir().unwrap();
        let fallback = StaticFallback {
            static_dir: dir.path().to_path_buf(),
            index: "index.html".into(),
        };
        let response = fallback.response_for_path("/missing").await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fallback_static_symlink_escape_returns_not_found() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"secret")
            .await
            .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.txt"),
        )
        .unwrap();
        let fallback = StaticFallback {
            static_dir: dir.path().to_path_buf(),
            index: "index.html".into(),
        };
        let response = fallback.response_for_path("/link.txt").await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn fallback_static_oversized_file_returns_payload_too_large() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("large.bin"),
            vec![b'x'; MAX_STATIC_RESPONSE_BYTES as usize + 1],
        )
        .await
        .unwrap();
        let fallback = StaticFallback {
            static_dir: dir.path().to_path_buf(),
            index: "index.html".into(),
        };
        let response = fallback.response_for_path("/large.bin").await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn reverse_proxy_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nproxied",
                    )
                    .await;
            }
        });
        let fallback = FallbackHandler::from_config(&FallbackConfig::ReverseProxy {
            upstream: format!("http://{addr}"),
        });
        let response = fallback
            .response_for(&Method::GET, "/anything")
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"proxied"));
    }

    #[tokio::test]
    async fn reverse_proxy_fallback_times_out_stalled_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let fallback = ReverseProxyFallback {
            upstream: format!("http://{addr}"),
            timeout: Duration::from_millis(50),
        };
        let err = fallback
            .response_for(&Method::GET, "/anything", &HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
    }

    #[tokio::test]
    async fn reverse_proxy_fallback_preserves_non_get_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut buf = [0u8; 512];
                while !request.ends_with(b"payload") {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8_lossy(&request);
                let request_lower = request.to_ascii_lowercase();
                assert!(request.starts_with("POST /base/submit?ok=1 HTTP/1.1\r\n"));
                assert!(request_lower.contains("\r\ncontent-length: 7\r\n"));
                assert!(request_lower.contains("\r\nuser-agent: fallback-test\r\n"));
                assert!(request.ends_with("\r\n\r\npayload"));
                assert!(!request.contains("Maverick-Fallback"));
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nserver: upstream-test\r\nlocation: /ok\r\nconnection: close\r\n\r\ncreated",
                    )
                    .await;
            }
        });
        let fallback = ReverseProxyFallback {
            upstream: format!("http://{addr}/base"),
            timeout: Duration::from_secs(1),
        };
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "fallback-test".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());

        let response = fallback
            .response_for(
                &Method::POST,
                "/submit?ok=1",
                &headers,
                Bytes::from_static(b"payload"),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["server"], "upstream-test");
        assert_eq!(response.headers()["location"], "/ok");
        assert!(!response.headers().contains_key("connection"));
        assert_eq!(response.body(), &Bytes::from_static(b"created"));
    }

    #[tokio::test]
    async fn reverse_proxy_fallback_decodes_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n",
                    )
                    .await;
            }
        });
        let fallback = ReverseProxyFallback {
            upstream: format!("http://{addr}"),
            timeout: Duration::from_secs(1),
        };

        let response = fallback
            .response_for(&Method::GET, "/", &HeaderMap::new(), Bytes::new())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("transfer-encoding"));
        assert_eq!(response.body(), &Bytes::from_static(b"wikipedia"));
    }

    #[tokio::test]
    async fn reverse_proxy_fallback_strips_connection_nominated_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: x-hidden-response\r\nx-hidden-response: secret\r\nx-visible-response: yes\r\n\r\nok",
                    )
                    .await;
            }
        });
        let fallback = ReverseProxyFallback {
            upstream: format!("http://{addr}"),
            timeout: Duration::from_secs(1),
        };
        let mut headers = HeaderMap::new();
        headers.insert("connection", "x-hidden-request".parse().unwrap());
        headers.insert("x-hidden-request", "secret".parse().unwrap());
        headers.insert("x-visible-request", "yes".parse().unwrap());

        let response = fallback
            .response_for(&Method::GET, "/", &headers, Bytes::new())
            .await
            .unwrap();
        let request = request_rx.await.unwrap().to_ascii_lowercase();

        assert!(!request.contains("x-hidden-request"));
        assert!(request.contains("x-visible-request: yes"));
        assert!(!response.headers().contains_key("connection"));
        assert!(!response.headers().contains_key("x-hidden-response"));
        assert_eq!(response.headers()["x-visible-response"], "yes");
    }

    #[tokio::test]
    async fn reverse_proxy_fallback_rejects_oversized_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = vec![b'x'; MAX_PROXY_RESPONSE_BYTES + 1];
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(headers.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            }
        });
        let fallback = ReverseProxyFallback {
            upstream: format!("http://{addr}"),
            timeout: Duration::from_secs(2),
        };

        let error = fallback
            .response_for(&Method::GET, "/", &HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("reverse proxy upstream body failed"),
            "{error:#}"
        );
    }
}
