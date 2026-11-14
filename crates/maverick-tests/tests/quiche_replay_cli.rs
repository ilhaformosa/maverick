#[path = "support/replay_archive.rs"]
mod replay_archive;

use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

#[test]
fn historical_binary_silently_rejects_synthetic_and_invalid_inputs() {
    // Cargo supplies the binary path independently of its internal build layout.
    let binary = env!("CARGO_BIN_EXE_quiche-fork-replay-verifier");
    let mut fixture = tempfile::Builder::new()
        .suffix(".crate")
        .tempfile()
        .unwrap();
    fixture
        .write_all(&replay_archive::gzip(&replay_archive::synthetic_tar()))
        .unwrap();
    fixture.flush().unwrap();

    for input in [fixture.path(), Path::new("relative.crate")] {
        let output = Command::new(binary)
            .arg(input)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    let system_temp = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    match std::fs::read_dir(Path::new(system_temp).join("maverick-b002-s2-replay")) {
        Ok(mut entries) => assert!(entries.next().is_none()),
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
    }
}
