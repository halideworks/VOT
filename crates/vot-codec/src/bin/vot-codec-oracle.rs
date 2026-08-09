use std::fmt::Write as _;
use std::io::{self, BufRead};

use vot_codec::frames::TypedFrame;
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
        if let Some(rest) = line.strip_prefix("session ") {
            println!("{}", session_line(rest));
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

/// Decodes one session authentication frame, envelope included, and reports
/// what it holds or why it was refused.
///
/// The re-encoding is what makes a vector catch an encoder that disagrees with
/// the decoder, which is the failure a single-direction check cannot see.
fn session_line(hex: &str) -> String {
    let Some(input) = decode_hex(hex) else {
        return "err|INVALID_HEX".to_string();
    };
    let limits = DecodeLimits {
        // The four session frames are known types, so the registered limits
        // apply and this bounds only a type that is not one of them.
        max_unknown_payload: 0,
        max_frames: 1,
    };
    let (frame, consumed) = match vot_codec::frames::decode(&input, limits) {
        Ok(decoded) => decoded,
        Err(error) => return format!("err|{}", frame_error_name(&error)),
    };
    if consumed != input.len() {
        return "err|TRAILING_BYTES".to_string();
    }
    let mut output = match &frame {
        TypedFrame::AuthContext(value) => {
            let mut line = format!(
                "ok|auth_context|{}|{}",
                encode_hex(&value.nonce),
                u64::from(value.binding == vot_codec::frames::Binding::ProofOfPossession)
            );
            for format in &value.formats {
                let _ = write!(line, "|{format}");
            }
            line
        }
        TypedFrame::SessionOpen(value) => format!(
            "ok|session_open|{}|{}|{}|{}|{}",
            encode_hex(&value.session_id),
            value.capability_format,
            encode_hex(&value.capability),
            encode_hex(&value.requested_scope),
            encode_hex(&value.binding_proof)
        ),
        TypedFrame::SessionAccept(value) => format!(
            "ok|session_accept|{}|{}",
            encode_hex(&value.session_id),
            encode_hex(&value.granted_scope)
        ),
        TypedFrame::SessionReject(value) => format!(
            "ok|session_reject|{}|{}|{}",
            encode_hex(&value.session_id),
            value.reason,
            encode_hex(value.detail.as_bytes())
        ),
        other => return format!("err|WRONG_FRAME_TYPE_{}", other.frame_type()),
    };
    let mut encoded = Vec::new();
    match vot_codec::frames::encode(&frame, &mut encoded) {
        Ok(()) => {
            let _ = write!(output, "|re={}", encode_hex(&encoded));
            output
        }
        Err(error) => format!("err|{}", frame_error_name(&error)),
    }
}

fn frame_error_name(error: &vot_codec::frames::Error) -> &'static str {
    use vot_codec::frames::Error as FrameError;

    match error {
        FrameError::Envelope(inner) => error_name(inner),
        FrameError::WrongFrameType(_) => "WRONG_FRAME_TYPE",
        FrameError::Malformed => "MALFORMED_FRAME",
        FrameError::InvalidValue => "INVALID_VALUE",
        FrameError::TooLarge => "FRAME_TOO_LARGE",
        FrameError::Manifest => "MANIFEST_INVALID",
        FrameError::Seal => "SEAL_INVALID",
        FrameError::Receipt => "RECEIPT_INVALID",
    }
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
    fn session_lines_report_values_and_refusals() {
        // The oracle is what a validator written from the specification talks
        // to, so its own encoding of a result has to be exercised. These are
        // vectors from test-vectors/wire/session-authentication.json.
        let minimal = "0719a4000001500000000000000000000000000000000002000380";
        assert_eq!(
            session_line(minimal),
            format!("ok|auth_context|{}|0|re={minimal}", "00".repeat(16))
        );
        let open = "091da600000150111111111111111111111111111111110201034004400540";
        assert_eq!(
            session_line(open),
            format!("ok|session_open|{}|1||||re={open}", "11".repeat(16))
        );
        let accept = "0b1fa3000001502222222222222222222222222222222202480a0a0a0a0a0a0a0a";
        assert_eq!(
            session_line(accept),
            format!(
                "ok|session_accept|{}|{}|re={accept}",
                "22".repeat(16),
                "0a".repeat(8)
            )
        );
        let reject = "0d20a400000150333333333333333333333333333333330219020303657374616c65";
        assert_eq!(
            session_line(reject),
            format!(
                "ok|session_reject|{}|515|7374616c65|re={reject}",
                "33".repeat(16)
            )
        );

        assert_eq!(
            session_line("071ba40000015000000000000000000000000000000000020003820201"),
            "err|INVALID_VALUE"
        );
        assert_eq!(
            session_line(
                "072aa40000015000000000000000000000000000000000020003910102030405060708090a0b0c0d0e0f1011"
            ),
            "err|FRAME_TOO_LARGE"
        );
        assert_eq!(
            session_line("0d1da40000015022222222222222222222222222222222021902010362fffe"),
            "err|MALFORMED_FRAME"
        );
        // A frame this oracle does not answer for is named, not misreported.
        assert_eq!(session_line("2d00"), "err|MALFORMED_FRAME");
        assert_eq!(session_line("0"), "err|INVALID_HEX");
        // Bytes past the frame the envelope declares are the caller's mistake,
        // and reporting the frame alone would hide a vector that carries them.
        assert_eq!(session_line(&format!("{accept}00")), "err|TRAILING_BYTES");
    }

    #[test]
    fn negotiation_lines_report_values_and_refusals() {
        // The oracle is what a validator written from the specification talks
        // to, so its own encoding of a result has to be exercised.
        assert_eq!(hello_line("050000"), "ok|5|0|re=050000");
        assert_eq!(hello_line("050003000206"), "ok|5|0|0|2|6|re=050003000206");
        // A server-role payload decodes rather than being reported as the role
        // mismatch a client-side session would see.
        assert_eq!(hello_line("050100"), "ok|5|1|re=050100");
        assert_eq!(hello_line("030000"), "err|UNSUPPORTED_VERSION");
        // The revision this build replaced is now one it will not speak.
        assert_eq!(hello_line("040000"), "err|UNSUPPORTED_VERSION");
        assert_eq!(hello_line("050200"), "err|MALFORMED_FRAME");
        assert_eq!(hello_line("05004101"), "err|RESOURCE_LIMIT");
        assert_eq!(hello_line("0"), "err|INVALID_HEX");

        // Every registered setting reported, not only the first and last. A
        // dropped field would leave a validator comparing fewer values than it
        // thought it was and still passing.
        assert_eq!(
            settings_line(""),
            "ok|1=1048576|3=262144|5=1048576|7=16|9=90000\
             |re=01801000000380040000058010000007100980015f90"
                .replace(' ', "")
        );
        assert_eq!(settings_line("410101"), "err|INVALID_SETTING");
        // ADR-0035 retired 0x0b, 0x20, and 0x22. The first was critical, so a
        // peer still sending it closes the session under the same code any
        // unknown critical setting closes under; the other two are optional
        // and are ignored, which is what forward compatibility means.
        assert_eq!(settings_line("0b80004e20"), "err|INVALID_SETTING");
        assert_eq!(
            settings_line("2041f4"),
            settings_line(""),
            "a retired optional setting changes nothing"
        );
        assert_eq!(settings_line("2201"), settings_line(""));
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
