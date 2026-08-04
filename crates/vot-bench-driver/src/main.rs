//! Backend driver for `tools/run_benchmark.py`.
//!
//! The runner supplies one case through `VOT_BENCH_*` and reads one JSON object
//! from stdout. Every number printed is measured here; nothing is defaulted or
//! inferred, and a case this driver cannot honestly run is an error rather than
//! a fabricated result.

fn main() {
    if let Err(error) = run() {
        eprintln!("vot-bench-driver: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), vot_bench_driver::Error> {
    let config = vot_bench_driver::Config::from_env()?;
    // A role makes this process one half of a two-machine run, started by hand
    // on each machine; without one the case runs whole, in process, as the
    // runner expects.
    let two_machine = std::env::var("VOT_BENCH_ROLE").is_ok_and(|value| !value.is_empty());
    let measurement = if two_machine {
        role_measure(&config)?
    } else {
        vot_bench_driver::measure(&config)?
    };
    println!("{}", measurement.to_json());
    Ok(())
}

#[cfg(any(feature = "msquic", feature = "quiche"))]
fn role_measure(
    config: &vot_bench_driver::Config,
) -> Result<vot_bench_driver::Measurement, vot_bench_driver::Error> {
    vot_bench_driver::role::measure(config)
}

#[cfg(not(any(feature = "msquic", feature = "quiche")))]
fn role_measure(
    _config: &vot_bench_driver::Config,
) -> Result<vot_bench_driver::Measurement, vot_bench_driver::Error> {
    Err(vot_bench_driver::Error::Unsupported(
        "VOT_BENCH_ROLE needs a real backend; build with --features msquic,quiche".to_owned(),
    ))
}
