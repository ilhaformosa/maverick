#![forbid(unsafe_code)]

// Compile the actual H2 TLS settings and UDP test driver against the newer
// upstream APIs. This fixture has its own lockfile, not a second linked TLS
// backend or a change to the shipping client's dependencies.
#[path = "../../../../maverick-client/src/browser_tls.rs"]
mod browser_tls;
#[path = "../../../src/bin/backend-capture-lab/quiche_loopback.rs"]
mod loopback;
#[path = "../../../../maverick-client/src/tls_distrust.rs"]
mod tls_distrust;

use anyhow::{ensure, Result};
use maverick_core::auth::{
    ClientHello, ClientHelloV2, ClientHelloV2Params, ServerHello, ServerHelloV2,
    ServerHelloV2Params, TlsChannelBinding, FEATURE_TLS_CHANNEL_BINDING,
};
use maverick_core::{Mode, SecretString};
use quiche::h3::{self, Header};

#[path = "../src/tls.rs"]
mod tls;
use tls::{binding, pair, Peer};

const TUNNEL_PATH: &str = "/loopback-auth";
const AUTH_EPOCH: u64 = 7;

#[derive(Clone, Copy)]
enum Version {
    V1,
    V2,
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    WrongCredential,
    OtherClientConnection,
    OtherServerConnection,
    MissingBinding,
    MissingServerBinding,
}

fn request(
    version: Version,
    secret: &SecretString,
    binding: Option<TlsChannelBinding>,
) -> Result<(Vec<u8>, [u8; 32])> {
    let flags = if binding.is_some() {
        FEATURE_TLS_CHANNEL_BINDING
    } else {
        0
    };
    match version {
        Version::V1 => {
            let hello = ClientHello::try_new_with_channel_binding(
                "loopback-test",
                secret,
                TUNNEL_PATH,
                Mode::Stable,
                flags,
                binding,
            )?;
            Ok((hello.encode(), hello.client_nonce))
        }
        Version::V2 => {
            let hello = ClientHelloV2::new_with_channel_binding(ClientHelloV2Params {
                credential_hint: b"loopback-test".to_vec(),
                secret,
                auth_epoch: AUTH_EPOCH,
                tunnel_path: TUNNEL_PATH,
                mode: Mode::Stable,
                feature_flags: flags,
                rotation_flags: 0,
                channel_binding: binding,
            })?;
            Ok((hello.encode()?, hello.client_nonce))
        }
    }
}

fn response(
    version: Version,
    body: &[u8],
    secret: &SecretString,
    connection_binding: TlsChannelBinding,
    reply_binding: Option<TlsChannelBinding>,
) -> Result<Option<Vec<u8>>> {
    let selected_flags = if reply_binding.is_some() {
        FEATURE_TLS_CHANNEL_BINDING
    } else {
        0
    };
    // This test requires binding. The product's complete credential lookup,
    // replay, epoch, and admission policy remain outside this transport probe.
    match version {
        Version::V1 => {
            let hello = ClientHello::decode(body)?;
            if hello.feature_flags & FEATURE_TLS_CHANNEL_BINDING == 0
                || !hello.verify_with_channel_binding(secret, TUNNEL_PATH, Some(connection_binding))
            {
                return Ok(None);
            }
            Ok(Some(
                ServerHello::try_new_with_channel_binding(
                    secret,
                    &hello.client_nonce,
                    4096,
                    1,
                    selected_flags,
                    reply_binding,
                )?
                .encode(),
            ))
        }
        Version::V2 => {
            let hello = ClientHelloV2::decode(body)?;
            if hello.feature_flags & FEATURE_TLS_CHANNEL_BINDING == 0
                || !hello.verify_with_channel_binding(secret, TUNNEL_PATH, Some(connection_binding))
            {
                return Ok(None);
            }
            Ok(Some(
                ServerHelloV2::try_new_with_channel_binding(ServerHelloV2Params {
                    secret,
                    selected_epoch: AUTH_EPOCH,
                    client_nonce: &hello.client_nonce,
                    max_frame_size: 4096,
                    max_concurrent_flows: 1,
                    feature_flags_selected: selected_flags,
                    rotation_window_secs: 0,
                    channel_binding: reply_binding,
                })?
                .encode()?,
            ))
        }
    }
}

fn exchange(version: Version, fault: Fault) -> Result<bool> {
    let mut connection = pair(Peer::Valid)?;
    connection.handshake()?;
    let client_binding = binding(&mut connection.client.conn)?;
    let server_binding = binding(&mut connection.server.conn)?;
    ensure!(
        client_binding == server_binding,
        "TLS exporter endpoints disagree"
    );
    let other_binding = if matches!(
        fault,
        Fault::OtherClientConnection | Fault::OtherServerConnection
    ) {
        let mut other = pair(Peer::Valid)?;
        other.handshake()?;
        let value = binding(&mut other.client.conn)?;
        ensure!(value != client_binding, "independent TLS exporters agree");
        other.shutdown()?;
        value
    } else {
        client_binding
    };
    let secret = SecretString::generate();
    let wrong_secret = SecretString::generate();
    let request_secret = if fault == Fault::WrongCredential {
        &wrong_secret
    } else {
        &secret
    };
    let request_binding = match fault {
        Fault::MissingBinding => None,
        Fault::OtherClientConnection => Some(other_binding),
        _ => Some(client_binding),
    };
    let (hello, nonce) = request(version, request_secret, request_binding)?;
    let mut config = h3::Config::new()?;
    config.set_max_field_section_size(4096);
    let mut client_h3 = h3::Connection::with_transport(&mut connection.client.conn, &config)?;
    let mut server_h3 = h3::Connection::with_transport(&mut connection.server.conn, &config)?;
    let headers = [
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"localhost"),
        Header::new(b":path", TUNNEL_PATH.as_bytes()),
    ];
    let stream = client_h3.send_request(&mut connection.client.conn, &headers, false)?;
    ensure!(
        client_h3.send_body(&mut connection.client.conn, stream, &hello, true)? == hello.len(),
        "partial client hello"
    );
    let received = connection.receive(&mut server_h3, true, &headers, &hello)?;
    let reply_binding = match fault {
        Fault::MissingServerBinding => None,
        Fault::OtherServerConnection => Some(other_binding),
        _ => Some(server_binding),
    };
    let reply = response(version, &received, &secret, server_binding, reply_binding)?;
    let accepted = reply.is_some();
    let reply = reply.unwrap_or_default();
    let status: &[u8] = if accepted { b"200" } else { b"403" };
    let headers = [Header::new(b":status", status)];
    server_h3.send_response(
        &mut connection.server.conn,
        stream,
        &headers,
        reply.is_empty(),
    )?;
    if !reply.is_empty() {
        ensure!(
            server_h3.send_body(&mut connection.server.conn, stream, &reply, true)? == reply.len(),
            "partial server hello"
        );
    }
    let received = connection.receive(&mut client_h3, false, &headers, &reply)?;
    let authenticated = accepted
        && match version {
            Version::V1 => {
                let hello = ServerHello::decode(&received)?;
                hello.feature_flags_selected & FEATURE_TLS_CHANNEL_BINDING != 0
                    && hello.verify_with_channel_binding(&secret, &nonce, Some(client_binding))
            }
            Version::V2 => {
                let hello = ServerHelloV2::decode(&received)?;
                hello.feature_flags_selected & FEATURE_TLS_CHANNEL_BINDING != 0
                    && hello.verify_with_channel_binding(&secret, &nonce, Some(client_binding))
            }
        };
    drop(client_h3);
    drop(server_h3);
    connection.shutdown()?;
    Ok(authenticated)
}

#[test]
fn upstream_quiche_runs_existing_loopback_probe() -> Result<()> {
    let report = loopback::run()?;
    assert_eq!((report.request_bytes, report.response_bytes), (25, 26));
    assert!(report.datagrams_sent > 0);
    Ok(())
}

#[test]
fn auth_v1_and_v2_complete_over_verified_h3() -> Result<()> {
    for version in [Version::V1, Version::V2] {
        assert!(exchange(version, Fault::None)?);
    }
    Ok(())
}

#[test]
fn wrong_credentials_are_rejected() -> Result<()> {
    rejects_auth(Fault::WrongCredential)
}

#[test]
fn client_hello_from_another_tls_connection_is_rejected() -> Result<()> {
    rejects_auth(Fault::OtherClientConnection)
}

#[test]
fn server_hello_bound_to_another_tls_connection_is_rejected() -> Result<()> {
    rejects_auth(Fault::OtherServerConnection)
}

#[test]
fn missing_channel_binding_is_rejected() -> Result<()> {
    rejects_auth(Fault::MissingBinding)
}

fn rejects_auth(fault: Fault) -> Result<()> {
    for version in [Version::V1, Version::V2] {
        assert!(!exchange(version, fault)?);
    }
    Ok(())
}

#[test]
fn server_cannot_omit_channel_binding() -> Result<()> {
    rejects_auth(Fault::MissingServerBinding)
}

#[test]
fn custom_tls_builder_rejects_untrusted_peer() -> Result<()> {
    rejects_tls(Peer::Untrusted)
}

#[test]
fn custom_tls_builder_checks_hostname() -> Result<()> {
    rejects_tls(Peer::WrongHostname)
}

#[test]
fn custom_tls_builder_enforces_verify_callback() -> Result<()> {
    rejects_tls(Peer::RejectedByPolicy)
}

fn rejects_tls(peer: Peer) -> Result<()> {
    let mut connection = pair(peer)?;
    let error = connection
        .handshake()
        .expect_err("invalid TLS peer was accepted");
    assert!(
        matches!(
            error.downcast_ref::<quiche::Error>(),
            Some(quiche::Error::TlsFail)
        ),
        "expected TLS verification failure, got {error}"
    );
    Ok(())
}
