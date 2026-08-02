//! Measures hashing throughput, so an argument about the verification ceiling
//! rests on a number from the machine in front of you.
//!
//! ```sh
//! cargo run --release -p vot-verifier --example hash_throughput
//! ```

use std::hint::black_box;
use std::time::Instant;

use vot_verifier::{StreamVerifier, Suite};

fn gigabits_per_second(bytes: u32, seconds: f64) -> f64 {
    (f64::from(bytes) * 8.0) / seconds / 1e9
}

fn measure(label: &str, bytes: u32, run: impl Fn(&[u8])) {
    let data = vec![0x5a_u8; bytes as usize];
    // One untimed pass, so the figure is not the cost of faulting in a gigabyte.
    run(&data);
    let started = Instant::now();
    run(&data);
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "{label:<24} {:7.2} Gb/s",
        gigabits_per_second(bytes, seconds)
    );
}

fn main() {
    let bytes: u32 = 1 << 30;
    println!("{} MiB per pass", bytes >> 20);
    measure("blake3 whole buffer", bytes, |data| {
        black_box(blake3::hash(data));
    });
    measure("vot blake3 verifier", bytes, |data| {
        let mut verifier = StreamVerifier::new(Suite::Blake3Bao64);
        verifier.update(data).unwrap();
        black_box(verifier.finish().unwrap());
    });
    measure("vot sha256 verifier", bytes, |data| {
        let mut verifier = StreamVerifier::new(Suite::Sha256Bep52);
        verifier.update(data).unwrap();
        black_box(verifier.finish().unwrap());
    });
    println!(
        "logical cpus: {}",
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get)
    );
}
