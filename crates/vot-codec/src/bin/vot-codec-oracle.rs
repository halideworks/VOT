use std::fmt::Write as _;
use std::io::{self, BufRead};

use vot_codec::{
    DecodeError, DecodeLimits, DecodedFrame, EndpointRole, HelloError, Settings, SettingsError,
    decode_all, decode_hello, decode_settings, encode_hello, encode_settings,
};

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        // A bare hex line is still the frame oracle; a prefix selects a
        // negotiation payload decoder.
        if let Some(rest) = line.strip_prefix("hello ") {
            println!("{}", hello_line(rest));
            continue;
        }
        if let Some(rest) = line.strip_prefix("settings ") {
            println!("{}", settings_line(rest));
            continue;
        }
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

/// Decodes one HELLO payload and reports what it holds, or why it was refused.
/// The role is not fixed, so a vector can check a server-role payload.
fn hello_line(hex: &str) -> String {
    let Some(payload) = decode_hex(hex) else {
        return "err|INVALID_HEX".to_string();
    };
    let client = decode_hello(&payload, EndpointRole::Client);
    let hello = match client {
        Ok(hello) => hello,
        Err(HelloError::RoleMismatch { .. }) => {
            match decode_hello(&payload, EndpointRole::Server) {
                Ok(hello) => hello,
                Err(error) => return format!("err|{}", hello_error_name(&error)),
            }
        }
        Err(error) => return format!("err|{}", hello_error_name(&error)),
    };
    let mut output = format!("ok|{}|{}", hello.draft_revision, hello.endpoint_role as u64);
    for extension in &hello.extensions {
        let _ = write!(output, "|{extension}");
    }
    // Re-encoded, so a vector catches an encoder that disagrees with the
    // decoder.
    let mut encoded = Vec::new();
    match encode_hello(&hello, &mut encoded) {
        Ok(()) => format!("{output}|re={}", encode_hex(&encoded)),
        Err(error) => format!("err|{}", hello_error_name(&error)),
    }
}

/// Decodes one SETTINGS payload and reports every registered value it leaves.
fn settings_line(hex: &str) -> String {
    let Some(payload) = decode_hex(hex) else {
        return "err|INVALID_HEX".to_string();
    };
    let settings = match decode_settings(&payload) {
        Ok(settings) => settings,
        Err(error) => return format!("err|{}", settings_error_name(&error)),
    };
    let mut output = String::from("ok");
    for identifier in vot_codec::REGISTERED_SETTINGS {
        let _ = write!(
            output,
            "|{identifier}={}",
            setting_value(&settings, identifier)
        );
    }
    let mut encoded = Vec::new();
    match encode_settings(&settings, &mut encoded) {
        Ok(()) => format!("{output}|re={}", encode_hex(&encoded)),
        Err(error) => format!("err|{}", settings_error_name(&error)),
    }
}

fn setting_value(settings: &Settings, identifier: u64) -> u64 {
    use vot_codec::setting_id as id;

    match identifier {
        id::MAX_CONTROL_FRAME_PAYLOAD => settings.max_control_frame_payload,
        id::MAX_DATA_RECORD_PAYLOAD => settings.max_data_record_payload,
        id::MAX_MANIFEST_PAGE_PAYLOAD => settings.max_manifest_page_payload,
        id::RELIABLE_LANE_LIMIT => settings.reliable_lane_limit,
        id::IDLE_TIMEOUT_MS => settings.idle_timeout_ms,
        id::ACTIVE_KEEPALIVE_MS => settings.active_keepalive_ms,
        id::COMPRESSION_MIN_GAIN_BPS => settings.compression_min_gain_bps,
        id::TELEMETRY_LEVEL => settings.telemetry_level,
        _ => u64::MAX,
    }
}

/// Names a refusal by the `spec/registries.md` code it closes under, which is
/// the vocabulary a second implementation shares.
const fn code_name(code: u16) -> &'static str {
    use vot_codec::error_code as registry;

    match code {
        registry::UNKNOWN_CRITICAL_FRAME => "UNKNOWN_CRITICAL_FRAME",
        registry::FRAME_TOO_LARGE => "FRAME_TOO_LARGE",
        registry::UNSUPPORTED_VERSION => "UNSUPPORTED_VERSION",
        registry::INVALID_SETTING => "INVALID_SETTING",
        registry::DUPLICATE_SETTING => "DUPLICATE_SETTING",
        registry::RESOURCE_LIMIT => "RESOURCE_LIMIT",
        registry::CARRIER_UNAVAILABLE => "CARRIER_UNAVAILABLE",
        _ => "MALFORMED_FRAME",
    }
}

fn hello_error_name(error: &HelloError) -> &'static str {
    code_name(error.protocol_code())
}

fn settings_error_name(error: &SettingsError) -> &'static str {
    code_name(error.protocol_code())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers_cover_digits_letters_and_invalid_input() {
        assert_eq!(decode_hex("00af10"), Some(vec![0, 0xaf, 0x10]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(encode_hex(&[0, 1, 0xaf, 0xff]), "0001afff");
    }

    #[test]
    fn negotiation_lines_report_values_and_refusals() {
        // The oracle is what a validator written from the specification talks
        // to, so its own encoding of a result has to be exercised.
        assert_eq!(hello_line("040000"), "ok|4|0|re=040000");
        assert_eq!(hello_line("040003000206"), "ok|4|0|0|2|6|re=040003000206");
        // A server-role payload decodes rather than being reported as the role
        // mismatch a client-side session would see.
        assert_eq!(hello_line("040100"), "ok|4|1|re=040100");
        assert_eq!(hello_line("030000"), "err|UNSUPPORTED_VERSION");
        assert_eq!(hello_line("040200"), "err|MALFORMED_FRAME");
        assert_eq!(hello_line("04004101"), "err|RESOURCE_LIMIT");
        assert_eq!(hello_line("0"), "err|INVALID_HEX");

        // Every registered setting reported, not only the first and last. A
        // dropped field would leave a validator comparing fewer values than it
        // thought it was and still passing.
        assert_eq!(
            settings_line(""),
            "ok|1=1048576|3=262144|5=1048576|7=16|9=90000|11=20000|32=500|34=1\
             |re=01801000000380040000058010000007100980015f900b80004e202041f42201"
                .replace(' ', "")
        );
        assert_eq!(settings_line("410101"), "err|INVALID_SETTING");
        assert_eq!(settings_line("07100710"), "err|DUPLICATE_SETTING");
        assert_eq!(settings_line("01"), "err|MALFORMED_FRAME");
        assert_eq!(settings_line("0"), "err|INVALID_HEX");
        assert_eq!(setting_value(&Settings::default(), 0xffff), u64::MAX);
        // Named by the registered code, so a partial payload and a trailing
        // byte report what the peer would actually see.
        assert_eq!(
            code_name(vot_codec::error_code::MALFORMED_FRAME),
            "MALFORMED_FRAME"
        );
        assert_eq!(
            code_name(vot_codec::error_code::FRAME_TOO_LARGE),
            "FRAME_TOO_LARGE"
        );
        assert_eq!(
            code_name(vot_codec::error_code::UNKNOWN_CRITICAL_FRAME),
            "UNKNOWN_CRITICAL_FRAME"
        );
        assert_eq!(
            code_name(vot_codec::error_code::CARRIER_UNAVAILABLE),
            "CARRIER_UNAVAILABLE"
        );
        assert_eq!(code_name(0xffff), "MALFORMED_FRAME");
    }

    #[test]
    fn error_names_cover_protocol_errors() {
        assert_eq!(
            error_name(&DecodeError::Incomplete {
                needed: 2,
                available: 1
            }),
            "INCOMPLETE"
        );
        assert_eq!(
            error_name(&DecodeError::FrameTooLarge {
                frame_type: 1,
                length: 2,
                limit: 1
            }),
            "FRAME_TOO_LARGE"
        );
        assert_eq!(
            error_name(&DecodeError::UnknownCritical(1)),
            "UNKNOWN_CRITICAL_FRAME"
        );
        assert_eq!(
            error_name(&DecodeError::TooManyFrames { limit: 1 }),
            "TOO_MANY_FRAMES"
        );
        assert_eq!(
            error_name(&DecodeError::ValueOutOfRange(1)),
            "MALFORMED_FRAME"
        );
        assert_eq!(error_name(&DecodeError::InvalidLimits), "MALFORMED_FRAME");
        assert_eq!(
            error_name(&DecodeError::LengthOverflow(1)),
            "MALFORMED_FRAME"
        );
    }
}
