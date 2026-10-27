use crate::{browser_tls, loopback};
use anyhow::{ensure, Result};
use boring::ssl::{SslContext, SslFiletype, SslMethod, SslRef, SslVerifyMode, SslVersion};
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use tempfile::TempDir;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Peer {
    Valid,
    Untrusted,
    WrongHostname,
    RejectedByPolicy,
}

pub(crate) fn pair(peer: Peer) -> Result<loopback::Pair> {
    let fixture = TempDir::new()?;
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = fixture.path().join("cert.pem");
    let key_path = fixture.path().join("key.pem");
    let trust_path = fixture.path().join("trust.pem");
    loopback::write_private(&cert_path, identity.cert.pem().as_bytes())?;
    loopback::write_private(&key_path, identity.key_pair.serialize_pem().as_bytes())?;
    let trust = if peer == Peer::Untrusted {
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?
            .cert
            .pem()
    } else {
        identity.cert.pem()
    };
    loopback::write_private(&trust_path, trust.as_bytes())?;

    let mut client = SslContext::builder(SslMethod::tls())?;
    client.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    client.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    browser_tls::configure(&mut client)?;
    client.set_ca_file(&trust_path)?;
    if peer == Peer::RejectedByPolicy {
        // The connection must actually honor an installed verification hook.
        client.set_verify_callback(SslVerifyMode::PEER, |_, _| false);
    }
    let mut server = SslContext::builder(SslMethod::tls())?;
    server.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    server.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    server.set_certificate_chain_file(&cert_path)?;
    server.set_private_key_file(&key_path, SslFiletype::PEM)?;
    let client_config = loopback::configure_transport(
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, client)?,
    )?;
    let server_config = loopback::configure_transport(
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, server)?,
    )?;
    let hostname = if peer == Peer::WrongHostname {
        "wrong.localhost"
    } else {
        "localhost"
    };
    let mut pair = loopback::Pair::with_configs(fixture, hostname, client_config, server_config)?;
    let ssl: &mut SslRef = pair.client.conn.as_mut();
    ssl.set_enable_ech_grease(true);
    Ok(pair)
}

pub(crate) fn binding(connection: &mut quiche::Connection) -> Result<TlsChannelBinding> {
    let ssl: &mut SslRef = connection.as_mut();
    ensure!(
        ssl.version2() == Some(SslVersion::TLS1_3),
        "expected TLS 1.3"
    );
    let mut bytes = [0; 32];
    ssl.export_keying_material(
        &mut bytes,
        std::str::from_utf8(TLS_CHANNEL_BINDING_EXPORTER_LABEL)?,
        None,
    )?;
    Ok(TlsChannelBinding::new(bytes))
}
