#![cfg(feature = "proxy")]

use log::{Level, LevelFilter, Log, Metadata, Record};
use maverick_quiche_tls_auth::{proxy::PeerInput, smoke};
use std::sync::atomic::{AtomicUsize, Ordering};

static LOGGER: CountingLogger = CountingLogger;
static TRACE: AtomicUsize = AtomicUsize::new(0);
static H3: AtomicUsize = AtomicUsize::new(0);
static DEBUG: AtomicUsize = AtomicUsize::new(0);

struct CountingLogger;
impl Log for CountingLogger {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &Record<'_>) {
        // Never format, retain, or print real authentication/traffic arguments.
        if record.level() == Level::Trace {
            TRACE.fetch_add(1, Ordering::SeqCst);
        }
        if record.level() == Level::Debug {
            DEBUG.fetch_add(1, Ordering::SeqCst);
        }
        if record.target().starts_with("quiche::h3") {
            H3.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn flush(&self) {}
}

#[tokio::test]
async fn real_proxy_keeps_upstream_h3_logging_disabled_with_verbose_logger() -> anyhow::Result<()> {
    assert_eq!(log::STATIC_MAX_LEVEL, LevelFilter::Debug);
    log::set_logger(&LOGGER).map_err(|_| anyhow::anyhow!("logger already installed"))?;
    log::set_max_level(LevelFilter::Trace);
    log::debug!("synthetic logger positive control");
    assert_eq!(DEBUG.load(Ordering::SeqCst), 1);
    for v2 in [false, true] {
        for peer in [
            PeerInput::ClientPriority,
            PeerInput::ClientPushControls,
            PeerInput::ServerPushPromise,
        ] {
            assert_eq!(
                smoke::run_with_peer_input(v2, peer).await?,
                smoke::PAYLOAD_SIZE
            );
        }
    }
    assert_eq!(TRACE.load(Ordering::SeqCst), 0);
    assert_eq!(H3.load(Ordering::SeqCst), 0);
    Ok(())
}
