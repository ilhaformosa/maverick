use std::process::ExitCode;

use maverick_tests::backend_capture::{current_main_preflight, PreflightState};

#[cfg(feature = "quiche-candidate")]
#[path = "backend-capture-lab/quiche_loopback.rs"]
mod quiche_loopback;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "backend-capture-lab".to_owned());
    let command = args.next();
    if args.next().is_some() {
        eprintln!("usage: {program} preflight|quiche-loopback");
        return ExitCode::from(2);
    }
    match command.as_deref() {
        Some("preflight") => preflight(),
        Some("quiche-loopback") => quiche_loopback(),
        _ => {
            eprintln!("usage: {program} preflight|quiche-loopback");
            ExitCode::from(2)
        }
    }
}

fn preflight() -> ExitCode {
    let report = current_main_preflight();
    match report.require_all_ready() {
        Ok(()) => {
            println!("B-001 preflight: READY");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("B-001 preflight: RED");
            for subject in report.subjects {
                match subject.state {
                    PreflightState::Ready => println!("{}: ready", subject.subject.label()),
                    PreflightState::Blocked(blocker) => {
                        println!("{}: {blocker}", subject.subject.label());
                    }
                }
            }
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "quiche-candidate")]
fn quiche_loopback() -> ExitCode {
    match quiche_loopback::run() {
        Ok(report) => {
            println!("quiche loopback: PASS (local candidate experiment only)");
            println!("verified certificate and hostname; negotiated h3");
            println!(
                "request/response: {}/{} bytes; UDP datagrams sent: {}",
                report.request_bytes, report.response_bytes, report.datagrams_sent
            );
            println!("connections closed; sockets and temporary credentials released");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("quiche loopback: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "quiche-candidate"))]
fn quiche_loopback() -> ExitCode {
    eprintln!("quiche loopback requires the default-off quiche-candidate build feature");
    ExitCode::from(2)
}
