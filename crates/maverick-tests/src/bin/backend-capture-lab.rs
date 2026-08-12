use std::process::ExitCode;

use maverick_tests::backend_capture::{current_main_preflight, PreflightState};

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "backend-capture-lab".to_owned());
    if args.next().as_deref() != Some("preflight") || args.next().is_some() {
        eprintln!("usage: {program} preflight");
        return ExitCode::from(2);
    }

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
