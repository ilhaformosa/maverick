use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, Request, StatusCode};
use maverick_client::transport;
use maverick_core::auth::ClientHello;
use maverick_core::config::{ClientConfig, FallbackConfig, SecretString};
use maverick_core::frame::{Frame, FrameType};
use maverick_core::grpc::encode_grpc_frame;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

#[allow(dead_code)]
#[path = "../../tests/support/mod.rs"]
mod support;

use support::{HarnessOptions, MaverickHarness};

#[derive(Debug, Serialize)]
struct ActiveProbeReport {
    schema_version: u32,
    generated_at_utc: String,
    git_revision: String,
    safety_scope: &'static str,
    claims: ReportClaims,
    scenarios: Vec<ScenarioResult>,
    timing_distributions: Vec<TimingDistribution>,
    coverage: Vec<CoverageItem>,
}

#[derive(Debug, Serialize)]
struct ReportClaims {
    perfect_origin_indistinguishability: bool,
    censorship_resistance: bool,
}

#[derive(Debug, Serialize)]
struct ScenarioResult {
    id: &'static str,
    fallback_kind: &'static str,
    reference_kind: &'static str,
    equal_response_shape: bool,
    differences: Vec<String>,
    reference: ResponseObservation,
    observed: ResponseObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ResponseObservation {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    trailers: BTreeMap<String, Vec<String>>,
    body_length: usize,
    body_sha256: String,
    elapsed_micros: u128,
}

#[derive(Debug, Serialize)]
struct CoverageItem {
    surface: &'static str,
    status: &'static str,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
struct TimingDistribution {
    id: &'static str,
    sample_count: usize,
    reference: TimingStats,
    observed: TimingStats,
    parity_claim: bool,
}

#[derive(Debug, Serialize)]
struct TimingStats {
    min_micros: u128,
    median_micros: u128,
    p95_micros: u128,
    max_micros: u128,
}

#[derive(Debug, Serialize)]
struct ActiveProbeSummary<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    git_revision: &'a str,
    safety_scope: &'a str,
    claims: &'a ReportClaims,
    scenarios: Vec<ScenarioSummary<'a>>,
    timing_distributions: &'a [TimingDistribution],
    coverage: &'a [CoverageItem],
}

#[derive(Debug, Serialize)]
struct ScenarioSummary<'a> {
    id: &'a str,
    fallback_kind: &'a str,
    equal_response_shape: bool,
    differences: &'a [String],
}

#[tokio::main]
async fn main() -> Result<()> {
    let output_dir = parse_output_dir()?;
    let mut scenarios = static_fallback_scenarios().await?;
    let reverse_proxy = reverse_proxy_scenarios().await?;
    scenarios.extend(reverse_proxy.scenarios);
    let report = ActiveProbeReport {
        schema_version: 2,
        generated_at_utc: OffsetDateTime::now_utc().format(&Rfc3339)?,
        git_revision: git_revision(),
        safety_scope: "loopback listeners and OS-assigned ephemeral ports only",
        claims: ReportClaims {
            perfect_origin_indistinguishability: false,
            censorship_resistance: false,
        },
        scenarios,
        timing_distributions: reverse_proxy.timing_distributions,
        coverage: vec![
            CoverageItem {
                surface: "H2 static fallback response shape",
                status: "measured",
                reason: "ordinary, malformed, and bad-auth requests are compared",
            },
            CoverageItem {
                surface: "H2 reverse-proxy response shape",
                status: "measured",
                reason: "direct origin comparisons cover methods, paths, queries, headers, bodies, malformed auth, bad auth, and auth-rate limiting",
            },
            CoverageItem {
                surface: "fallback admission exhaustion",
                status: "integration_regression",
                reason: "fallback_overload_returns_generic_http_without_protocol_detail mechanically checks the bounded 503 difference",
            },
            CoverageItem {
                surface: "TLS server fingerprint and ALPN parity",
                status: "measured_separately",
                reason: "the fingerprint lab records Maverick TLS and ALPN; no origin-specific parity claim is made",
            },
            CoverageItem {
                surface: "WebSocket fallback parity",
                status: "known_difference",
                reason: "the explicit WebSocket carrier rejects a wrong upgrade path instead of invoking the HTTP fallback",
            },
            CoverageItem {
                surface: "H3 fallback parity",
                status: "feature_gated_regression",
                reason: "the H3 harness checks ordinary, malformed, bad-auth, replay, and preserved-body fallback paths",
            },
            CoverageItem {
                surface: "HTTPS reverse-proxy upstream",
                status: "unsupported_evaluated",
                reason: "v1.1 accepts only HTTP upstreams and converts unsupported or failed upstreams to a generic 502 response",
            },
            CoverageItem {
                surface: "streaming bodies and trailers",
                status: "bounded_buffering_residual",
                reason: "maintained Hyper parsing is used, but fallback bodies remain capped and buffered and upstream trailers are not forwarded",
            },
            CoverageItem {
                surface: "timing distribution parity",
                status: "measured_no_parity_claim",
                reason: "repeated loopback distributions are recorded for diagnosis without an indistinguishability threshold",
            },
        ],
    };

    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    let json_path = output_dir.join("active-probe-report.json");
    let summary_path = output_dir.join("active-probe-summary.json");
    let markdown_path = output_dir.join("active-probe-report.md");
    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)?;
    fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summarize(&report))?,
    )?;
    fs::write(&markdown_path, render_markdown(&report))?;
    println!("wrote {}", json_path.display());
    println!("wrote {}", summary_path.display());
    println!("wrote {}", markdown_path.display());
    Ok(())
}

fn parse_output_dir() -> Result<PathBuf> {
    let mut output_dir = PathBuf::from("runtime-evidence/active-probe-lab");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => {
                output_dir = PathBuf::from(args.next().context("--output-dir requires a path")?);
            }
            "-h" | "--help" => {
                println!("usage: active-probe-lab [--output-dir PATH]");
                std::process::exit(0);
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }
    Ok(output_dir)
}

async fn static_fallback_scenarios() -> Result<Vec<ScenarioResult>> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let ordinary = h2_request(
        &config,
        Method::GET,
        config.server.tunnel_path.as_str(),
        HeaderMap::new(),
        Bytes::new(),
    )
    .await?;
    let malformed = h2_request(
        &config,
        Method::POST,
        config.server.tunnel_path.as_str(),
        grpc_hello_headers(),
        encoded_hello_frame(vec![0]),
    )
    .await?;
    let bad_auth = bad_auth_request(&config).await?;
    let results = vec![
        compare(
            "static_malformed_matches_ordinary",
            "static",
            "same-path ordinary fallback",
            ordinary.clone(),
            malformed,
        ),
        compare(
            "static_bad_auth_matches_ordinary",
            "static",
            "same-path ordinary fallback",
            ordinary,
            bad_auth,
        ),
    ];
    fixture.shutdown().await?;
    Ok(results)
}

struct ReverseProxyLabResult {
    scenarios: Vec<ScenarioResult>,
    timing_distributions: Vec<TimingDistribution>,
}

struct ProbeCase {
    id: &'static str,
    method: Method,
    path: &'static str,
    headers: HeaderMap,
    body: Bytes,
}

async fn reverse_proxy_scenarios() -> Result<ReverseProxyLabResult> {
    let origin = ProbeOrigin::start().await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{}", origin.addr),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let cases = vec![
        ProbeCase {
            id: "reverse_proxy_ordinary_matches_origin",
            method: Method::POST,
            path: "/probe/ordinary",
            headers: grpc_hello_headers(),
            body: Bytes::from_static(b"ordinary-body"),
        },
        ProbeCase {
            id: "reverse_proxy_get_path_query_headers_matches_origin",
            method: Method::GET,
            path: "/assets/app.js?cache=1&mode=probe",
            headers: probe_headers("get-case"),
            body: Bytes::new(),
        },
        ProbeCase {
            id: "reverse_proxy_head_matches_origin",
            method: Method::HEAD,
            path: "/probe/head?value=1",
            headers: probe_headers("head-case"),
            body: Bytes::new(),
        },
        ProbeCase {
            id: "reverse_proxy_put_body_matches_origin",
            method: Method::PUT,
            path: "/probe/resource/42",
            headers: probe_headers("put-case"),
            body: Bytes::from_static(b"put-body"),
        },
        ProbeCase {
            id: "reverse_proxy_patch_body_matches_origin",
            method: Method::PATCH,
            path: "/probe/resource/42?partial=true",
            headers: probe_headers("patch-case"),
            body: Bytes::from_static(b"patch-body"),
        },
        ProbeCase {
            id: "reverse_proxy_delete_body_matches_origin",
            method: Method::DELETE,
            path: "/probe/resource/42",
            headers: probe_headers("delete-case"),
            body: Bytes::from_static(b"delete-body"),
        },
        ProbeCase {
            id: "reverse_proxy_options_matches_origin",
            method: Method::OPTIONS,
            path: "/probe/options",
            headers: probe_headers("options-case"),
            body: Bytes::new(),
        },
    ];
    let mut results = Vec::new();
    for case in cases {
        let direct = origin
            .request(
                case.method.clone(),
                case.path,
                &case.headers,
                case.body.clone(),
            )
            .await?;
        let proxied = h2_request(&config, case.method, case.path, case.headers, case.body).await?;
        results.push(compare(
            case.id,
            "reverse_proxy",
            "direct deterministic origin",
            direct,
            proxied,
        ));
    }

    let malformed_body = encoded_hello_frame(vec![0]);
    let malformed_headers = grpc_hello_headers();
    let direct_malformed = origin
        .request(
            Method::POST,
            config.server.tunnel_path.as_str(),
            &malformed_headers,
            malformed_body.clone(),
        )
        .await?;
    let proxied_malformed = h2_request(
        &config,
        Method::POST,
        config.server.tunnel_path.as_str(),
        malformed_headers,
        malformed_body,
    )
    .await?;

    let mut bad = config.clone();
    bad.server.secret = SecretString::generate();
    let bad_hello = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();
    let bad_body = encoded_hello_frame(bad_hello);
    let bad_headers = grpc_hello_headers();
    let direct_bad_auth = origin
        .request(
            Method::POST,
            bad.server.tunnel_path.as_str(),
            &bad_headers,
            bad_body.clone(),
        )
        .await?;
    let proxied_bad_auth = h2_request(
        &bad,
        Method::POST,
        bad.server.tunnel_path.as_str(),
        bad_headers,
        bad_body,
    )
    .await?;

    results.push(compare(
        "reverse_proxy_malformed_matches_origin",
        "reverse_proxy",
        "direct deterministic origin",
        direct_malformed,
        proxied_malformed,
    ));
    results.push(compare(
        "reverse_proxy_bad_auth_matches_origin",
        "reverse_proxy",
        "direct deterministic origin",
        direct_bad_auth,
        proxied_bad_auth,
    ));

    let mut reference_timings = Vec::new();
    let mut observed_timings = Vec::new();
    for _ in 0..12 {
        reference_timings.push(
            origin
                .request(
                    Method::GET,
                    "/probe/timing",
                    &HeaderMap::new(),
                    Bytes::new(),
                )
                .await?
                .elapsed_micros,
        );
        observed_timings.push(
            h2_request(
                &config,
                Method::GET,
                "/probe/timing",
                HeaderMap::new(),
                Bytes::new(),
            )
            .await?
            .elapsed_micros,
        );
    }
    fixture.shutdown().await?;

    let rate_fixture = MaverickHarness::start_with_options(HarnessOptions {
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{}", origin.addr),
        }),
        server_max_auth_failures_per_window: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let rate_config = rate_fixture.client_config();
    let first_bad_auth = bad_auth_request(&rate_config).await?;
    let rate_limited_bad_auth = bad_auth_request(&rate_config).await?;
    results.push(compare(
        "reverse_proxy_rate_limited_bad_auth_matches_first",
        "reverse_proxy",
        "first bad-auth fallback",
        first_bad_auth,
        rate_limited_bad_auth,
    ));
    rate_fixture.shutdown().await?;

    let closed_listener = TcpListener::bind("127.0.0.1:0").await?;
    let closed_addr = closed_listener.local_addr()?;
    drop(closed_listener);
    let failure_fixture = MaverickHarness::start_with_options(HarnessOptions {
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{closed_addr}"),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let failed = h2_request(
        &failure_fixture.client_config(),
        Method::GET,
        "/probe/upstream-failure",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await?;
    results.push(compare(
        "reverse_proxy_upstream_failure_is_generic_502",
        "reverse_proxy",
        "generic fallback failure policy",
        expected_text_response(StatusCode::BAD_GATEWAY, b"Bad Gateway"),
        failed,
    ));
    failure_fixture.shutdown().await?;
    origin.shutdown().await?;
    Ok(ReverseProxyLabResult {
        scenarios: results,
        timing_distributions: vec![TimingDistribution {
            id: "direct_origin_vs_maverick_reverse_proxy_loopback",
            sample_count: reference_timings.len(),
            reference: timing_stats(reference_timings),
            observed: timing_stats(observed_timings),
            parity_claim: false,
        }],
    })
}

async fn bad_auth_request(config: &ClientConfig) -> Result<ResponseObservation> {
    let mut bad = config.clone();
    bad.server.secret = SecretString::generate();
    let hello = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();
    h2_request(
        &bad,
        Method::POST,
        bad.server.tunnel_path.as_str(),
        grpc_hello_headers(),
        encoded_hello_frame(hello),
    )
    .await
}

async fn h2_request(
    config: &ClientConfig,
    method: Method,
    uri: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Result<ResponseObservation> {
    let started = Instant::now();
    let mut h2 = match transport::connect(config).await? {
        transport::TunnelRequestSender::H2(h2) => h2,
        transport::TunnelRequestSender::CloudflareWs(_) => bail!("expected H2 transport"),
        #[cfg(feature = "h3")]
        transport::TunnelRequestSender::H3(_) => bail!("expected H2 transport"),
    };
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let end_stream = body.is_empty();
    let (response_future, mut send_stream) =
        h2.sender.send_request(builder.body(())?, end_stream)?;
    if !body.is_empty() {
        send_stream.send_data(body, true)?;
    }
    let response = response_future.await?;
    response_observation(response, started).await
}

async fn response_observation(
    response: http::Response<h2::RecvStream>,
    started: Instant,
) -> Result<ResponseObservation> {
    let status = response.status().as_u16();
    let headers = normalize_headers(response.headers());
    let mut body_stream = response.into_body();
    let mut body = BytesMut::new();
    while let Some(chunk) = body_stream.data().await {
        body.extend_from_slice(&chunk?);
    }
    let trailers = body_stream
        .trailers()
        .await?
        .map(|trailers| normalize_headers(&trailers))
        .unwrap_or_default();
    Ok(observation_from_parts(
        status,
        headers,
        trailers,
        &body,
        started.elapsed(),
    ))
}

fn compare(
    id: &'static str,
    fallback_kind: &'static str,
    reference_kind: &'static str,
    reference: ResponseObservation,
    observed: ResponseObservation,
) -> ScenarioResult {
    let mut differences = Vec::new();
    if reference.status != observed.status {
        differences.push("status".into());
    }
    if reference.headers != observed.headers {
        differences.push("headers".into());
    }
    if reference.trailers != observed.trailers {
        differences.push("trailers".into());
    }
    if reference.body_length != observed.body_length {
        differences.push("body_length".into());
    }
    if reference.body_sha256 != observed.body_sha256 {
        differences.push("body_sha256".into());
    }
    ScenarioResult {
        id,
        fallback_kind,
        reference_kind,
        equal_response_shape: differences.is_empty(),
        differences,
        reference,
        observed,
    }
}

fn grpc_hello_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    headers.insert("te", "trailers".parse().unwrap());
    headers.insert("x-probe-profile", "deterministic".parse().unwrap());
    headers
}

fn probe_headers(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("accept", "text/plain".parse().unwrap());
    headers.insert("x-probe-echo", value.parse().unwrap());
    headers
}

fn expected_text_response(status: StatusCode, body: &[u8]) -> ResponseObservation {
    let mut headers = BTreeMap::new();
    headers.insert(
        "content-type".into(),
        vec!["text/plain; charset=utf-8".into()],
    );
    observation_from_parts(
        status.as_u16(),
        headers,
        BTreeMap::new(),
        body,
        Duration::ZERO,
    )
}

fn timing_stats(mut samples: Vec<u128>) -> TimingStats {
    samples.sort_unstable();
    let percentile = |numerator: usize| {
        let index = (samples.len() - 1) * numerator / 100;
        samples[index]
    };
    TimingStats {
        min_micros: samples[0],
        median_micros: percentile(50),
        p95_micros: percentile(95),
        max_micros: *samples.last().unwrap(),
    }
}

fn encoded_hello_frame(payload: Vec<u8>) -> Bytes {
    encode_grpc_frame(Frame::new(FrameType::ClientHello, 0, 0, payload), 65_536)
        .expect("bounded synthetic ClientHello frame")
}

struct ProbeOrigin {
    addr: std::net::SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl ProbeOrigin {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        tokio::spawn(async move {
                            if let Err(error) = serve_origin_connection(stream).await {
                                eprintln!("probe origin connection failed: {error}");
                            }
                        });
                    }
                }
            }
            Ok(())
        });
        Ok(Self {
            addr,
            shutdown_tx,
            task,
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<ResponseObservation> {
        let started = Instant::now();
        let mut stream = TcpStream::connect(self.addr).await?;
        let mut request = format!(
            "{} {path} HTTP/1.1\r\nHost: reference.invalid\r\nConnection: close\r\nContent-Length: {}\r\n",
            method.as_str(),
            body.len()
        );
        for (name, value) in headers {
            if name.as_str().eq_ignore_ascii_case("te") {
                continue;
            }
            request.push_str(name.as_str());
            request.push_str(": ");
            request.push_str(value.to_str()?);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&body).await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
        parse_origin_response(&response, started.elapsed())
    }

    async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        self.task.await?
    }
}

async fn serve_origin_connection(mut stream: TcpStream) -> Result<()> {
    let request = read_http1_request(&mut stream).await?;
    let first_line = request
        .headers
        .split("\r\n")
        .next()
        .context("origin request line missing")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("UNKNOWN");
    let path = parts.next().unwrap_or("/");
    let echo = request_header_value(&request.headers, "x-probe-echo").unwrap_or("none");
    let body = format!(
        "method={method};path={path};body_length={};echo={echo};profile=deterministic",
        request.body.len()
    );
    let response_headers = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\nx-origin-profile: deterministic\r\nx-request-echo: {echo}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response_headers.as_bytes()).await?;
    if method != "HEAD" {
        stream.write_all(body.as_bytes()).await?;
    }
    Ok(())
}

fn request_header_value<'a>(headers: &'a str, expected: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        line.split_once(':')
            .and_then(|(name, value)| name.eq_ignore_ascii_case(expected).then_some(value.trim()))
    })
}

struct Http1Request {
    headers: String,
    body: Vec<u8>,
}

async fn read_http1_request(stream: &mut TcpStream) -> Result<Http1Request> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await??;
        if read == 0 {
            bail!("origin request closed before headers completed");
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 128 * 1024 {
            bail!("origin request exceeded lab limit");
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let read = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await??;
        if read == 0 {
            bail!("origin request closed before body completed");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(Http1Request {
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn parse_origin_response(input: &[u8], elapsed: Duration) -> Result<ResponseObservation> {
    let header_end = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("origin response headers missing")?;
    let header_text = String::from_utf8(input[..header_end].to_vec())?;
    let mut lines = header_text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("origin response status missing")?
        .parse()?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("connection") {
                continue;
            }
            headers
                .entry(name.trim().to_ascii_lowercase())
                .or_insert_with(Vec::new)
                .push(value.trim().to_owned());
        }
    }
    Ok(observation_from_parts(
        status,
        headers,
        BTreeMap::new(),
        &input[header_end + 4..],
        elapsed,
    ))
}

fn observation_from_parts(
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    trailers: BTreeMap<String, Vec<String>>,
    body: &[u8],
    elapsed: Duration,
) -> ResponseObservation {
    ResponseObservation {
        status,
        headers,
        trailers,
        body_length: body.len(),
        body_sha256: sha256_hex(body),
        elapsed_micros: elapsed.as_micros(),
    }
}

fn normalize_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut normalized = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        normalized
            .entry(name.as_str().to_ascii_lowercase())
            .or_default()
            .push(value.to_str().unwrap_or("<non-visible>").to_owned());
    }
    for values in normalized.values_mut() {
        values.sort();
    }
    normalized
}

fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_owned())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn summarize(report: &ActiveProbeReport) -> ActiveProbeSummary<'_> {
    ActiveProbeSummary {
        schema_version: report.schema_version,
        generated_at_utc: &report.generated_at_utc,
        git_revision: &report.git_revision,
        safety_scope: report.safety_scope,
        claims: &report.claims,
        scenarios: report
            .scenarios
            .iter()
            .map(|scenario| ScenarioSummary {
                id: scenario.id,
                fallback_kind: scenario.fallback_kind,
                equal_response_shape: scenario.equal_response_shape,
                differences: &scenario.differences,
            })
            .collect(),
        timing_distributions: &report.timing_distributions,
        coverage: &report.coverage,
    }
}

fn render_markdown(report: &ActiveProbeReport) -> String {
    let mut output = String::new();
    output.push_str("# Maverick Active-Probe Lab Report\n\n");
    output.push_str("Status: loopback-only engineering evidence. This is not a perfect-origin-indistinguishability or censorship-resistance claim.\n\n");
    output.push_str(&format!("- Generated UTC: `{}`\n", report.generated_at_utc));
    output.push_str(&format!("- Git revision: `{}`\n", report.git_revision));
    output.push_str(&format!("- Safety scope: {}.\n\n", report.safety_scope));
    output.push_str("| scenario | fallback | equal response shape | differences |\n");
    output.push_str("| --- | --- | --- | --- |\n");
    for scenario in &report.scenarios {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            scenario.id,
            scenario.fallback_kind,
            scenario.equal_response_shape,
            if scenario.differences.is_empty() {
                "-".into()
            } else {
                scenario.differences.join(", ")
            }
        ));
    }
    output.push_str("\n## Timing Distributions\n\n");
    output.push_str(
        "| comparison | samples | reference median us | observed median us | parity claim |\n",
    );
    output.push_str("| --- | ---: | ---: | ---: | --- |\n");
    for timing in &report.timing_distributions {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            timing.id,
            timing.sample_count,
            timing.reference.median_micros,
            timing.observed.median_micros,
            timing.parity_claim
        ));
    }
    output.push_str("\n## Coverage\n\n");
    output.push_str("| surface | status | reason |\n");
    output.push_str("| --- | --- | --- |\n");
    for item in &report.coverage {
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            item.surface, item.status, item.reason
        ));
    }
    output.push_str("\nTiming values are loopback diagnostics only; no timing parity or indistinguishability threshold is claimed.\n");
    output
}
