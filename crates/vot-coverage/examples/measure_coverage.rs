//! Run with `cargo run --release -p vot-coverage --example measure_coverage`.

use std::hint::black_box;
use std::time::Instant;
use vot_coverage::{Check, Coverage, Reserve};

fn main() {
    for reservations in [false, true] {
        let mut samples = Vec::new();
        for _ in 0..7 {
            let started = Instant::now();
            for _ in 0..200 {
                let mut coverage = Coverage::new();
                for parity in 0..2 {
                    for index in 0..4096 {
                        let offset = black_box((index * 2053 % 4096) * 2 + parity);
                        if reservations {
                            let Reserve::New(held) = coverage.reserve(offset, 1).unwrap() else {
                                panic!("new range");
                            };
                            coverage.commit_reservation(held);
                        } else {
                            let Check::New(booking) = coverage.check(offset, 1).unwrap() else {
                                panic!("new range");
                            };
                            booking.commit();
                        }
                    }
                }
                assert!(black_box(&coverage).is_complete(8192));
            }
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        println!("reservations={reservations}: median {:?}", samples[3]);
    }
}
