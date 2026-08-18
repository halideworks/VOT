use super::*;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Just enough JSON for `test-vectors/fec/vectors.json`.
#[derive(Debug)]
enum Json {
    Number(u64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map_or_else(|| panic!("no field {key}"), |(_, value)| value),
            other => panic!("{key} on {other:?}"),
        }
    }

    fn u64(&self) -> u64 {
        match self {
            Json::Number(n) => *n,
            other => panic!("not a number: {other:?}"),
        }
    }

    fn usize(&self) -> usize {
        usize::try_from(self.u64()).expect("fits")
    }

    fn str(&self) -> &str {
        match self {
            Json::String(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    fn array(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            other => panic!("not an array: {other:?}"),
        }
    }

    fn usizes(&self) -> Vec<usize> {
        self.array().iter().map(Json::usize).collect()
    }

    fn u8(&self) -> u8 {
        u8::try_from(self.u64()).expect("a byte")
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) {
        self.skip_space();
        assert_eq!(self.bytes[self.at], byte, "at {}", self.at);
        self.at += 1;
    }

    fn value(&mut self) -> Json {
        self.skip_space();
        match self.bytes[self.at] {
            b'{' => {
                self.at += 1;
                let mut fields = Vec::new();
                loop {
                    self.skip_space();
                    if self.bytes[self.at] == b'}' {
                        self.at += 1;
                        return Json::Object(fields);
                    }
                    let key = self.string();
                    self.eat(b':');
                    let value = self.value();
                    fields.push((key, value));
                    self.skip_space();
                    if self.bytes[self.at] == b',' {
                        self.at += 1;
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_space();
                    if self.bytes[self.at] == b']' {
                        self.at += 1;
                        return Json::Array(items);
                    }
                    items.push(self.value());
                    self.skip_space();
                    if self.bytes[self.at] == b',' {
                        self.at += 1;
                    }
                }
            }
            b'"' => Json::String(self.string()),
            _ => {
                let start = self.at;
                while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_digit() {
                    self.at += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("ascii");
                Json::Number(text.parse().unwrap_or_else(|_| panic!("number at {start}")))
            }
        }
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let start = self.at;
        while self.bytes[self.at] != b'"' {
            assert_ne!(self.bytes[self.at], b'\\', "escapes are not needed here");
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("utf-8");
        self.at += 1;
        text.to_owned()
    }
}

fn vectors() -> Json {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/fec/vectors.json"
    ));
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value();
    parser.skip_space();
    assert_eq!(parser.at, text.len(), "trailing bytes");
    assert_eq!(value.get("format").str(), "vot-datagram-fec-v0");
    value
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Source symbol `esi` of the vector pattern.
fn pattern(esi: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| u8::try_from((i * 17 + esi * 7 + 3) % 251).expect("below 251"))
        .collect()
}

fn geometry_of(case: &Json) -> Geometry {
    Geometry::new(
        case.get("source_count").usize(),
        case.get("repair_count").usize(),
        case.get("symbol_length").usize(),
    )
    .expect("a valid vector geometry")
}

fn sha256(parts: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

#[test]
fn the_limits_are_the_vectors_limits() {
    let limits = vectors();
    let limits = limits.get("limits");
    assert_eq!(limits.get("max_source_count").usize(), MAX_SOURCE_SYMBOLS);
    assert_eq!(limits.get("max_repair_count").usize(), MAX_REPAIR_SYMBOLS);
    assert_eq!(limits.get("max_symbol_length").usize(), MAX_SYMBOL_LENGTH);
}

#[test]
fn the_field_matches_the_vectors() {
    let vectors = vectors();
    let field = vectors.get("field");
    assert_eq!(field.get("polynomial").u64(), 0x11D);
    assert_eq!(field.get("generator").u64(), 2);
    assert!(field.get("exp_first_16").array().len() == 16);
    assert!(field.get("products").array().len() >= 6);
    assert!(field.get("inverses").array().len() >= 6);
    let mut power = 1_u8;
    for (i, expected) in field.get("exp_first_16").usizes().into_iter().enumerate() {
        assert_eq!(usize::from(power), expected, "exp[{i}]");
        power = gf::mul(power, 2);
    }
    for product in field.get("products").array() {
        let a = product.get("a").u8();
        let b = product.get("b").u8();
        assert_eq!(
            usize::from(gf::mul(a, b)),
            product.get("product").usize(),
            "{a}*{b}"
        );
    }
    for inverse in field.get("inverses").array() {
        let a = inverse.get("a").u8();
        assert_eq!(
            usize::from(gf::inv(a)),
            inverse.get("inverse").usize(),
            "inv({a})"
        );
    }
}

#[test]
fn the_generator_rows_match_the_vectors() {
    let vectors = vectors();
    let matrices = vectors.get("matrices").array();
    assert!(matrices.len() >= 4);
    for matrix in matrices {
        let k = matrix.get("source_count").usize();
        let r = matrix.get("repair_count").usize();
        let geometry = Geometry::new(k, r, 1).unwrap();
        let mut rows = Vec::with_capacity(r);
        for i in 0..r {
            let mut row = vec![0_u8; k];
            geometry.generator_row(i, &mut row);
            rows.push(row);
        }
        assert_eq!(
            rows[0].iter().map(|b| usize::from(*b)).collect::<Vec<_>>(),
            matrix.get("first_row").usizes(),
            "k={k} r={r}"
        );
        assert_eq!(
            sha256(&rows),
            matrix.get("matrix_sha256").str(),
            "k={k} r={r}"
        );
    }
}

#[test]
fn encode_and_decode_match_the_vectors() {
    let vectors = vectors();
    let cases = vectors.get("encode").array();
    assert!(cases.len() >= 9);
    for case in cases {
        let name = case.get("name").str();
        let geometry = geometry_of(case);
        let source: Vec<Vec<u8>> = (0..geometry.source_count())
            .map(|esi| pattern(esi, geometry.symbol_length()))
            .collect();
        let borrowed: Vec<&[u8]> = source.iter().map(Vec::as_slice).collect();
        let repair = encode(geometry, &borrowed).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected: Vec<Vec<u8>> = case
            .get("repair_hex")
            .array()
            .iter()
            .map(|s| hex(s.str()))
            .collect();
        assert_eq!(repair, expected, "{name} repair symbols");
        assert_eq!(sha256(&repair), case.get("repair_sha256").str(), "{name}");

        let erased = case.get("erased").usizes();
        let all: Vec<&[u8]> = borrowed
            .iter()
            .copied()
            .chain(repair.iter().map(Vec::as_slice))
            .collect();
        // Present in reverse so the decoder's ordering, not the caller's, is
        // what the vector pins.
        let received: Vec<(usize, &[u8])> = all
            .iter()
            .enumerate()
            .rev()
            .filter(|(esi, _)| !erased.contains(esi))
            .map(|(esi, symbol)| (esi, *symbol))
            .collect();
        let decoded = decode(geometry, &received).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(decoded, source, "{name} reconstruction");
        assert_eq!(sha256(&decoded), case.get("decoded_sha256").str(), "{name}");
    }
}

#[test]
fn insufficient_symbols_reconstruct_nothing() {
    let vectors = vectors();
    let cases = vectors.get("insufficient").array();
    assert!(cases.len() >= 3);
    for case in cases {
        let name = case.get("name").str();
        assert_eq!(case.get("outcome").str(), "INSUFFICIENT_SYMBOLS");
        let geometry = geometry_of(case);
        let source: Vec<Vec<u8>> = (0..geometry.source_count())
            .map(|esi| pattern(esi, geometry.symbol_length()))
            .collect();
        let borrowed: Vec<&[u8]> = source.iter().map(Vec::as_slice).collect();
        let repair = encode(geometry, &borrowed).unwrap();
        let erased = case.get("erased").usizes();
        let received: Vec<(usize, &[u8])> = borrowed
            .iter()
            .copied()
            .chain(repair.iter().map(Vec::as_slice))
            .enumerate()
            .filter(|(esi, _)| !erased.contains(esi))
            .collect();
        assert_eq!(
            decode(geometry, &received),
            Err(Error::InsufficientSymbols),
            "{name}"
        );
    }
}

#[test]
fn an_invalid_symbol_fails_the_whole_call() {
    let vectors = vectors();
    let cases = vectors.get("invalid_symbol").array();
    assert!(cases.len() >= 3);
    for case in cases {
        let name = case.get("name").str();
        assert_eq!(case.get("outcome").str(), "INVALID_SYMBOL");
        let geometry = geometry_of(case);
        let bad_esi = case.get("invalid_esi").usize();
        let bad_length = case.get("invalid_length").usize();
        let mut owned: Vec<(usize, Vec<u8>)> = (0..geometry.source_count())
            .map(|esi| (esi, pattern(esi, geometry.symbol_length())))
            .collect();
        owned.retain(|(esi, _)| *esi != bad_esi);
        owned.push((bad_esi, pattern(bad_esi, bad_length)));
        let received: Vec<(usize, &[u8])> =
            owned.iter().map(|(esi, s)| (*esi, s.as_slice())).collect();
        assert_eq!(
            decode(geometry, &received),
            Err(Error::InvalidSymbol),
            "{name}"
        );
    }
    // A repeated ESI is the same refusal, and so is a wrong source count or
    // length on the encode side.
    let geometry = Geometry::new(2, 1, 2).unwrap();
    let a = [1_u8, 2];
    assert_eq!(
        decode(geometry, &[(0, &a), (0, &a)]),
        Err(Error::InvalidSymbol)
    );
    assert_eq!(encode(geometry, &[&a]), Err(Error::InvalidSymbol));
    assert_eq!(encode(geometry, &[&a, &a[..1]]), Err(Error::InvalidSymbol));
}

#[test]
fn an_invalid_geometry_is_refused_before_anything_else() {
    let vectors = vectors();
    let cases = vectors.get("invalid_geometry").array();
    assert!(cases.len() >= 5);
    for case in cases {
        assert_eq!(case.get("outcome").str(), "INVALID_GEOMETRY");
        assert_eq!(
            Geometry::new(
                case.get("source_count").usize(),
                case.get("repair_count").usize(),
                case.get("symbol_length").usize(),
            ),
            Err(Error::InvalidGeometry),
            "{}",
            case.get("name").str()
        );
    }
    let edge = Geometry::new(MAX_SOURCE_SYMBOLS, MAX_REPAIR_SYMBOLS, MAX_SYMBOL_LENGTH).unwrap();
    assert_eq!(edge.symbol_count(), 80);
    assert_eq!(MAX_SYMBOLS, 80);
    assert_eq!(edge.source_count(), 64);
    assert_eq!(edge.repair_count(), 16);
    assert_eq!(edge.symbol_length(), 65_535);
    assert_eq!(Geometry::new(1, 0, 1).unwrap().symbol_count(), 1);
}

#[test]
fn every_erasure_pattern_within_the_repair_count_decodes() {
    // Exhaustive over small geometries: every subset of k symbols out of
    // k + r reconstructs the sources, so the MDS claim holds where it can be
    // enumerated. 2^8 subsets at most per geometry.
    for (k, r) in [(1, 1), (2, 2), (3, 3), (4, 4), (5, 3), (6, 2)] {
        let geometry = Geometry::new(k, r, 3).unwrap();
        let source: Vec<Vec<u8>> = (0..k).map(|esi| pattern(esi + 11, 3)).collect();
        let borrowed: Vec<&[u8]> = source.iter().map(Vec::as_slice).collect();
        let repair = encode(geometry, &borrowed).unwrap();
        let all: Vec<&[u8]> = borrowed
            .iter()
            .copied()
            .chain(repair.iter().map(Vec::as_slice))
            .collect();
        let n = k + r;
        for mask in 0_u32..(1 << n) {
            let received: Vec<(usize, &[u8])> = (0..n)
                .filter(|esi| mask & (1 << esi) != 0)
                .map(|esi| (esi, all[esi]))
                .collect();
            let outcome = decode(geometry, &received);
            if received.len() >= k {
                assert_eq!(outcome.as_ref(), Ok(&source), "k={k} r={r} mask={mask:b}");
            } else {
                assert_eq!(
                    outcome,
                    Err(Error::InsufficientSymbols),
                    "k={k} r={r} mask={mask:b}"
                );
            }
        }
    }
}

#[test]
#[ignore = "performance measurement"]
fn decode_costs() {
    let geometry = Geometry::new(64, 8, 1024).unwrap();
    let source: Vec<Vec<u8>> = (0..64).map(|esi| pattern(esi, 1024)).collect();
    let borrowed: Vec<&[u8]> = source.iter().map(Vec::as_slice).collect();
    let repair = encode(geometry, &borrowed).unwrap();

    for missing in [1, 8] {
        let received: Vec<(usize, &[u8])> = borrowed
            .iter()
            .enumerate()
            .skip(missing)
            .map(|(esi, symbol)| (esi, *symbol))
            .chain(
                repair
                    .iter()
                    .take(missing)
                    .enumerate()
                    .map(|(i, symbol)| (64 + i, symbol.as_slice())),
            )
            .collect();
        let started = std::time::Instant::now();
        for _ in 0..200 {
            std::hint::black_box(decode(geometry, &received).unwrap());
        }
        eprintln!(
            "missing {missing}: {:?} per decode",
            started.elapsed() / 200
        );
    }
}

#[test]
fn errors_display() {
    assert_eq!(Error::InvalidGeometry.to_string(), "invalid FEC geometry");
    assert_eq!(Error::InvalidSymbol.to_string(), "invalid FEC symbol");
    assert_eq!(
        Error::InsufficientSymbols.to_string(),
        "insufficient FEC symbols"
    );
}
