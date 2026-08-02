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
    let measurement = vot_bench_driver::measure(&config)?;
    println!("{}", measurement.to_json());
    Ok(())
}
