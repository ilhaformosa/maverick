//! Anonymous host context for manual measurements, not performance thresholds.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

pub(super) fn sample() -> Result<Value> {
    let (load, memory) = platform_context()?;
    Ok(json!({
        "os": std::env::consts::OS,
        "available_parallelism": std::thread::available_parallelism()?.get(),
        "load_average_1m": load[0],
        "load_average_5m": load[1],
        "load_average_15m": load[2],
        "memory": memory,
    }))
}

fn parse_load_averages(text: &str) -> Result<[f64; 3]> {
    let values = text
        .trim_matches(|c: char| c.is_ascii_whitespace() || matches!(c, '{' | '}'))
        .split_whitespace()
        .take(3)
        .map(str::parse::<f64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 3 && values.iter().all(|v| v.is_finite() && *v >= 0.0),
        "host load averages are missing or invalid"
    );
    Ok([values[0], values[1], values[2]])
}

#[cfg(target_os = "macos")]
fn platform_context() -> Result<([f64; 3], Value)> {
    use std::process::Command;

    let read = |program: &str, args: &[&str]| -> Result<String> {
        let output = Command::new(program).args(args).output()?;
        ensure!(output.status.success(), "host context command failed");
        Ok(String::from_utf8(output.stdout)?)
    };
    let load = parse_load_averages(&read("sysctl", &["-n", "vm.loadavg"])?)?;
    let pressure = read("sysctl", &["-n", "kern.memorystatus_vm_pressure_level"])?
        .trim()
        .parse::<u32>()?;
    let vm = read("vm_stat", &[])?;
    Ok((
        load,
        json!({
            // Darwin dispatch pressure codes: 1 normal, 2 warning, 4 critical.
            // Retain the numeric code; it does not determine test success.
            "pressure_level": pressure,
            // Cumulative compressed swap I/O in pages, including maintenance I/O.
            "swapins_pages": parse_vm_counter(&vm, "Swapins")?,
            "swapouts_pages": parse_vm_counter(&vm, "Swapouts")?,
        }),
    ))
}

#[cfg(any(target_os = "macos", test))]
fn parse_vm_counter(text: &str, name: &str) -> Result<u64> {
    let value = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| (key.trim() == name).then_some(value.trim()))
        .with_context(|| format!("missing host VM counter {name}"))?;
    Ok(value.trim_end_matches('.').parse()?)
}

#[cfg(target_os = "linux")]
fn platform_context() -> Result<([f64; 3], Value)> {
    let load = parse_load_averages(&std::fs::read_to_string("/proc/loadavg")?)?;
    let memory = parse_linux_memory(&std::fs::read_to_string("/proc/meminfo")?)?;
    Ok((load, memory))
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_memory(text: &str) -> Result<Value> {
    let kib = |name: &str| -> Result<u64> {
        let value = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(key, value)| (key == name).then_some(value))
            .with_context(|| format!("missing host memory field {name}"))?;
        let mut fields = value.split_whitespace();
        let number = fields
            .next()
            .context("missing host memory value")?
            .parse()?;
        ensure!(fields.next() == Some("kB"), "unexpected host memory unit");
        Ok(number)
    };
    let swap_used = kib("SwapTotal")?
        .checked_sub(kib("SwapFree")?)
        .context("inconsistent host swap values")?;
    Ok(json!({
        // Linux available memory is an estimate, not Darwin's pressure code.
        "total_kib": kib("MemTotal")?,
        "available_kib": kib("MemAvailable")?,
        "swap_used_kib": swap_used,
    }))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_context() -> Result<([f64; 3], Value)> {
    anyhow::bail!("host resource sampling requires macOS or Linux")
}

#[test]
fn reads_both_load_formats_without_process_fields() -> Result<()> {
    assert_eq!(
        parse_load_averages("{ 1.25 2.50 3.75 }\n")?,
        [1.25, 2.5, 3.75]
    );
    assert_eq!(
        parse_load_averages("1.25 2.50 3.75 2/128 4321\n")?,
        [1.25, 2.5, 3.75]
    );
    assert!(parse_load_averages("1.0 2.0").is_err());
    assert!(parse_load_averages("NaN 1.0 2.0").is_err());
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn reads_native_host_context_without_performance_thresholds() -> Result<()> {
    // Exercise the real OS sources on both native CI platforms.
    println!("host_context {}", sample()?);
    Ok(())
}

#[test]
fn distinguishes_swap_activity_from_other_vm_counters() -> Result<()> {
    let vm = "Pageins: 999.\nPageouts: 888.\nSwapins: 12.\nSwapouts: 34.\n";
    assert_eq!(parse_vm_counter(vm, "Swapins")?, 12);
    assert_eq!(parse_vm_counter(vm, "Swapouts")?, 34);
    assert!(parse_vm_counter("Pageouts: 888.\n", "Swapouts").is_err());
    Ok(())
}

#[test]
fn keeps_linux_available_memory_and_swap_units() -> Result<()> {
    let memory = parse_linux_memory("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 650 kB\nSwapTotal: 512 kB\nSwapFree: 400 kB\n")?;
    assert_eq!(memory["total_kib"], 1000);
    assert_eq!(memory["available_kib"], 650);
    assert_eq!(memory["swap_used_kib"], 112);
    assert!(parse_linux_memory("MemFree: 100 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").is_err());
    Ok(())
}
