//! Measure source reading, object hashing, and manifest preparation separately.

use std::{fs::File, io::Read, path::PathBuf, time::Instant};
use vot_object::{ObjectBuilder, Suite};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().expect("read, hash, or manifest");
    let source = PathBuf::from(args.next().expect("SOURCE"));
    let started = Instant::now();
    if mode == "manifest" {
        let destination = PathBuf::from(args.next().expect("MANIFEST_DIRECTORY"));
        let (summary, sources) =
            vot_cli::build_manifest(&source, &destination, Suite::Blake3Bao64).unwrap();
        println!("summary={summary:?} objects={}", sources.len());
    } else {
        assert!(mode == "read" || mode == "hash");
        let mut file = File::open(source).unwrap();
        let length = file.metadata().unwrap().len();
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(length)).unwrap();
        let mut buffer = vec![0; 256 * 1024];
        let mut observed = 0_u64;
        loop {
            let read = file.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            observed += read as u64;
            if mode == "hash" {
                builder.update(&buffer[..read]).unwrap();
            } else {
                std::hint::black_box(&buffer[..read]);
            }
        }
        assert_eq!(observed, length);
        if mode == "hash" {
            println!("object={:?}", builder.finish().unwrap().object_id());
        }
        println!("bytes={length}");
    }
    println!(
        "mode={} seconds={:.6}",
        mode.to_str().unwrap(),
        started.elapsed().as_secs_f64()
    );
}
