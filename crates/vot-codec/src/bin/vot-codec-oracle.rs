use std::fmt::Write as _;
use std::io::{self, BufRead};

use vot_codec::{DecodeError, DecodeLimits, DecodedFrame, decode_all};

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let Some(input) = decode_hex(&line) else {
            println!("err|INVALID_HEX");
            continue;
        };
        match decode_all(&input, DecodeLimits::default()) {
            Ok(frames) => {
                let mut output = String::from("ok");
                for frame in frames {
                    match frame {
                        DecodedFrame::Known {
                            frame_type,
                            payload,
                        } => {
                            let _ = write!(output, "|k,{frame_type},{}", encode_hex(payload));
                        }
                        DecodedFrame::SkippedOptional {
                            frame_type,
                            payload_length,
                        } => {
                            let _ = write!(output, "|o,{frame_type},{payload_length}");
                        }
                    }
                }
                println!("{output}");
            }
            Err(error) => println!("err|{}", error_name(&error)),
        }
    }
    Ok(())
}

fn error_name(error: &DecodeError) -> &'static str {
    match error {
        DecodeError::Incomplete { .. } => "INCOMPLETE",
        DecodeError::FrameTooLarge { .. } => "FRAME_TOO_LARGE",
        DecodeError::UnknownCritical(_) => "UNKNOWN_CRITICAL_FRAME",
        DecodeError::TooManyFrames { .. } => "TOO_MANY_FRAMES",
        DecodeError::ValueOutOfRange(_)
        | DecodeError::InvalidLimits
        | DecodeError::LengthOverflow(_) => "MALFORMED_FRAME",
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some(decode_nibble(pair[0])? * 16 + decode_nibble(pair[1])?))
        .collect()
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
