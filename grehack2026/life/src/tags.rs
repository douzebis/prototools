// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The tag channel of spec 0377: the client hides a bit field in a request's
//! field tags (canonical or not), and the server reads it back.
//!
//! Both sides go through the prototext text render, so the library is the one
//! source of truth for which rendered lines are field records (S3) and how a
//! tag's canonicity shows (`tag_ohb`). The client appends `; tag_ohb: 1` to
//! the lines a set bit selects and re-encodes (S6); the server reads which
//! lines carry `tag_ohb` (S3). A terminator `1` bit frames a message inside
//! the bit field (S3a).

use prototext_core::{
    parse_schema, render_as_bytes, render_as_text, MessageDescriptor, ParsedSchema, RenderOpts,
};

/// The two message roots the tag channel reads and writes: requests, from the
/// server's decode and the client's encode; responses, the other way round
/// (spec 0379 S1).
pub const REQUEST: &str = "grehack.life.v1.StepRequest";
pub const RESPONSE: &str = "grehack.life.v1.StepResponse";

/// A boolean per field record, packed into bytes (spec 0377 S4).
///
/// Bit *i* is record *i*'s flag; bit 0 is the most significant bit of byte 0,
/// so the bytes read left to right as the fields were sent. `n` bits occupy
/// `n.div_ceil(8)` bytes, the last byte's unused low bits zero.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BitField {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitField {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, set: bool) {
        if self.bits.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if set {
            self.bytes[self.bits / 8] |= 1 << (7 - (self.bits % 8));
        }
        self.bits += 1;
    }

    pub fn bit(&self, i: usize) -> bool {
        i < self.bits && (self.bytes[i / 8] >> (7 - (i % 8))) & 1 == 1
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// A message framed for the tag channel (spec 0377 S3a): its bits, then a
    /// single `1` terminator. The empty message frames to an empty bit field
    /// — no terminator — so an all-canonical request carries nothing.
    pub fn frame_message(message: &[u8]) -> Self {
        let mut bits = BitField::new();
        if message.is_empty() {
            return bits;
        }
        for &byte in message {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1 == 1);
            }
        }
        bits.push(true); // terminator
        bits
    }

    /// The message this bit field frames (spec 0377 S3a): the bits strictly
    /// before the last `1`, regrouped into bytes. No `1` bit — the empty bit
    /// field included — means the empty message. A trailing partial byte
    /// (the convention does not require whole bytes) is dropped; the demo's
    /// payload is byte-aligned.
    pub fn recover_message(&self) -> Vec<u8> {
        let Some(terminator) = (0..self.bits).rev().find(|&i| self.bit(i)) else {
            return Vec::new();
        };
        let mut message = Vec::with_capacity(terminator / 8);
        for byte_start in (0..terminator).step_by(8) {
            if byte_start + 8 > terminator {
                break; // a partial final byte
            }
            let mut byte = 0u8;
            for bit in 0..8 {
                byte = (byte << 1) | u8::from(self.bit(byte_start + bit));
            }
            message.push(byte);
        }
        message
    }
}

/// The life schema for a root message (`REQUEST` or `RESPONSE`), built once
/// from the embedded descriptor (a lone `FileDescriptorProto`, which a
/// `FileDescriptorSet` wraps for `parse_schema`) and cached per root.
fn schema(root: &str) -> &'static ParsedSchema {
    use prost::Message;
    use prost_types::{FileDescriptorProto, FileDescriptorSet};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, &'static ParsedSchema>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(s) = cache.lock().unwrap().get(root) {
        return s;
    }
    let file = FileDescriptorProto::decode(crate::DESCRIPTOR)
        .expect("the embedded descriptor is written by build.rs");
    let set = FileDescriptorSet { file: vec![file] }.encode_to_vec();
    let parsed: &'static ParsedSchema = Box::leak(Box::new(
        parse_schema(&set, root).expect("the life schema holds the root"),
    ));
    cache.lock().unwrap().insert(root.to_string(), parsed);
    parsed
}

fn root_descriptor(root: &str) -> Option<MessageDescriptor> {
    schema(root).root_descriptor()
}

fn opts() -> RenderOpts {
    RenderOpts {
        assume_binary: true,
        include_annotations: true,
        indent: 1,
        expand_any: false,
        hide_unknown_fields: false,
        expand_message_set: false,
    }
}

/// One bit per field record in `message` (a `root` message), in render order:
/// 1 when the field's tag was non-canonical (spec 0377 S3).
pub fn read_tags(message: &[u8], root: &str) -> BitField {
    let text = render_as_text(message, root_descriptor(root).as_ref(), opts())
        .expect("a received message renders");
    let text = String::from_utf8(text).expect("prototext renders UTF-8");

    let mut bits = BitField::new();
    for line in text.lines() {
        if let Some(annotation) = in_scope(line) {
            bits.push(has_tag_ohb(annotation));
        }
    }
    bits
}

/// `message` (a `root` message) re-encoded so field record *i*'s tag is
/// non-canonical when `bits.bit(i)` is set (spec 0377 S6). Bits past the
/// field-record count are dropped (N5). Returns the modified wire bytes.
pub fn encode_tags(message: &[u8], bits: &BitField, root: &str) -> Vec<u8> {
    let text = render_as_text(message, root_descriptor(root).as_ref(), opts())
        .expect("the message renders");
    let text = String::from_utf8(text).expect("prototext renders UTF-8");

    let mut field = 0usize;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if in_scope(line).is_some() {
            if bits.bit(field) && !line.contains("tag_ohb") {
                out.push_str(line);
                out.push_str("; tag_ohb: 1");
            } else {
                out.push_str(line);
            }
            field += 1;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    render_as_bytes(out.as_bytes(), {
        let mut o = opts();
        o.assume_binary = false; // the input is now prototext text, not binary
        o
    })
    .expect("the modified text re-encodes")
    .into_owned()
}

/// The `#@` annotation of a line that is a field record, or `None` for a line
/// that is not one (spec 0377 S3): a `}`, the header, a blank line, a
/// malformed record, or a packed continuation.
fn in_scope(line: &str) -> Option<&str> {
    let annotation = line.split_once("#@")?.1;
    if !has_field_tag(annotation) {
        return None;
    }
    // A packed record's first line shows pack_size and is in scope; its later
    // element lines carry [packed=true] without pack_size and are values under
    // a tag already counted (spec 0377 N2).
    if annotation.contains("[packed=true]") && !annotation.contains("pack_size") {
        return None;
    }
    Some(annotation)
}

/// Whether the annotation carries a `= <number>` field tag. Guards against a
/// `[packed=true]` `=` counting as the tag: the field tag is ` = `, set off by
/// spaces (annotation format), and followed by digits.
fn has_field_tag(annotation: &str) -> bool {
    annotation.split(" = ").skip(1).any(|rest| {
        rest.trim_start()
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    })
}

/// Whether the annotation reports tag overhang (spec 0377 N3: only the tag,
/// not `val_ohb`, `len_ohb` or the per-element `ohb`).
fn has_tag_ohb(annotation: &str) -> bool {
    annotation
        .split(';')
        .any(|m| m.trim().starts_with("tag_ohb"))
}

// ── The factoring exchange (spec 0382) ───────────────────────────────────────

/// The server's half, as sent on the wire: the operator's bytes verbatim,
/// no wrapper. Nominally `"factor <N>"` (spec 0382 S1, S2), but the grehack
/// demo drops the prefix and sends the bytes as-is, so the client runs them
/// directly (the smuggled channel).
pub fn factor_request(digits: &[u8]) -> Vec<u8> {
    digits.to_vec()
}

/// The client's half: `"factors <f>*<f>*…"`, each `<f>` a prime `p` or
/// `p^e` (e ≥ 2), primes ascending, no spaces (spec 0382 S1).
pub fn factors_reply(factors: &[(u128, u32)]) -> String {
    format!("factors {}", render_factors(factors, "*"))
}

/// The factors as `2^3<sep>3^2<sep>5`: the reply uses `*`, the server's
/// display ` * ` (spec 0382 S4).
pub fn render_factors(factors: &[(u128, u32)], sep: &str) -> String {
    factors
        .iter()
        .map(|&(p, e)| {
            if e == 1 {
                p.to_string()
            } else {
                format!("{p}^{e}")
            }
        })
        .collect::<Vec<_>>()
        .join(sep)
}

/// The factors a `"factors …"` message carries, in the order sent, or `None`
/// for anything malformed (spec 0382 S1). Whether they are prime, ascending
/// and multiply to the awaited N is the server's check (S4), not the parse's.
pub fn parse_factors_reply(message: &[u8]) -> Option<Vec<(u128, u32)>> {
    let list = std::str::from_utf8(message)
        .ok()?
        .strip_prefix("factors ")?;
    list.split('*')
        .map(|f| match f.split_once('^') {
            None => Some((canonical(f)?, 1)),
            Some((p, e)) => {
                let e = u32::try_from(canonical(e)?).ok()?;
                (e >= 2).then_some((canonical(p)?, e))
            }
        })
        .collect()
}

/// The client's half for the special number 42 (spec 0383): `"fortune <text>"`,
/// where `<text>` is the fortune the client ran. Newlines are kept, so the
/// server displays the fortune on several lines; the other control bytes
/// (tabs, a stray carriage return) become spaces, and the ends are trimmed.
/// The server prints it rather than checking a factorization.
pub fn fortune_reply(text: &[u8]) -> Vec<u8> {
    let kept: Vec<u8> = text
        .iter()
        .map(|&b| {
            if b != b'\n' && b.is_ascii_control() {
                b' '
            } else {
                b
            }
        })
        .collect();
    [b"fortune ".as_slice(), kept.trim_ascii()].concat()
}

/// The fortune a `"fortune <text>"` message carries, or `None` for anything
/// else (spec 0383). The text is returned as sent, newlines and all. An
/// empty text is accepted: `"fortune "` yields an empty slice.
pub fn parse_fortune_reply(message: &[u8]) -> Option<&[u8]> {
    message.strip_prefix(b"fortune ")
}

/// A canonical decimal: ASCII digits, no leading zero (but `0` itself), no
/// sign, at most `u128::MAX`.
fn canonical(s: &str) -> Option<u128> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    ok.then(|| s.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn a_request() -> Vec<u8> {
        crate::pb::StepRequest {
            grid: Some(crate::pb::Grid {
                rows: vec![crate::pb::Row { cells: vec![1, 0] }],
            }),
            rules: Some(crate::pb::Rules {
                birth: Some(crate::pb::Range { min: 3, max: 3 }),
                survival: Some(crate::pb::Range { min: 2, max: 3 }),
                topology: 0,
            }),
            generation: 7,
        }
        .encode_to_vec()
    }

    fn rendered_fields(bytes: &[u8]) -> usize {
        let text = render_as_text(bytes, root_descriptor(REQUEST).as_ref(), opts()).unwrap();
        String::from_utf8(text)
            .unwrap()
            .lines()
            .filter(|l| in_scope(l).is_some())
            .count()
    }

    #[test]
    fn bits_pack_big_endian() {
        let mut b = BitField::new();
        assert!(b.is_empty());
        b.push(true);
        b.push(false);
        b.push(true);
        assert_eq!(b.len(), 3);
        assert_eq!(b.as_bytes(), &[0b1010_0000]);
        assert!(b.bit(0) && !b.bit(1) && b.bit(2) && !b.bit(3));
    }

    #[test]
    fn a_new_byte_opens_every_eight_bits() {
        for n in [0usize, 1, 7, 8, 9] {
            let mut b = BitField::new();
            for _ in 0..n {
                b.push(false);
            }
            assert_eq!(b.len(), n);
            assert_eq!(b.as_bytes().len(), n.div_ceil(8));
            assert!(b.as_bytes().iter().all(|&byte| byte == 0), "n={n}");
        }
    }

    #[test]
    fn a_message_frames_with_a_terminator_and_round_trips() {
        let framed = BitField::frame_message(b"Hi");
        assert_eq!(framed.len(), 8 * 2 + 1, "two bytes and a terminator");
        assert!(framed.bit(16), "terminator is the last bit");
        assert_eq!(framed.recover_message(), b"Hi");
    }

    #[test]
    fn the_empty_message_is_an_all_false_field() {
        assert_eq!(BitField::frame_message(b""), BitField::new());
        assert_eq!(BitField::new().recover_message(), b"");
        // Padding after the terminator is dropped.
        let mut padded = BitField::frame_message(b"x");
        for _ in 0..20 {
            padded.push(false);
        }
        assert_eq!(padded.recover_message(), b"x");
    }

    #[test]
    fn a_message_whose_last_bit_is_one_still_gets_a_terminator() {
        // 0xFF ends in a 1 bit; without a terminator it would be ambiguous.
        let framed = BitField::frame_message(&[0xFF]);
        assert_eq!(framed.len(), 9);
        assert_eq!(framed.recover_message(), &[0xFF]);
    }

    #[test]
    fn reading_a_canonical_request_is_all_zero() {
        let bytes = a_request();
        let bits = read_tags(&bytes, REQUEST);
        assert_eq!(bits.len(), 12);
        assert_eq!(bits.len(), rendered_fields(&bytes));
        assert!(bits.as_bytes().iter().all(|&b| b == 0));
    }

    /// A request with a 5×5 grid: about 36 field records, enough tags to
    /// carry a short message with its terminator.
    fn a_roomy_request() -> Vec<u8> {
        // A 20x20 grid: ~420 field records, enough tags for a short message
        // and its terminator (spec 0379 N4).
        crate::pb::StepRequest {
            grid: Some(crate::pb::Grid {
                rows: vec![crate::pb::Row { cells: vec![1; 20] }; 20],
            }),
            rules: Some(crate::pb::Rules {
                birth: Some(crate::pb::Range { min: 3, max: 3 }),
                survival: Some(crate::pb::Range { min: 2, max: 3 }),
                topology: 0,
            }),
            generation: 1,
        }
        .encode_to_vec()
    }

    #[test]
    fn encode_then_read_round_trips_a_message() {
        let request = a_roomy_request();
        let message = b"Hi";
        let framed = BitField::frame_message(message);
        assert!(
            framed.len() <= rendered_fields(&request),
            "message must fit"
        );
        let spoiled = encode_tags(&request, &framed, REQUEST);

        // Value-preserving: the spoiled bytes decode to the same StepRequest.
        assert_eq!(
            crate::pb::StepRequest::decode(&spoiled[..]).unwrap(),
            crate::pb::StepRequest::decode(&request[..]).unwrap()
        );
        // And the server's read recovers the message.
        assert_eq!(read_tags(&spoiled, REQUEST).recover_message(), message);
    }

    #[test]
    fn a_non_canonical_tag_sets_exactly_its_bit() {
        let bytes = a_request();
        let at = bytes
            .windows(2)
            .rposition(|w| w == [0x18, 0x07])
            .expect("generation: 7 is `18 07`");
        let mut spoiled = bytes.clone();
        spoiled.splice(at..at + 1, [0x98, 0x00]);
        // generation is the last of 12 records: bit 11.
        assert_eq!(read_tags(&bytes, REQUEST).as_bytes(), &[0x00, 0x00]);
        assert_eq!(
            read_tags(&spoiled, REQUEST).as_bytes(),
            &[0x00, 0b0001_0000]
        );
    }

    #[test]
    fn a_bit_field_longer_than_the_fields_is_truncated() {
        let request = a_request();
        let n = rendered_fields(&request);
        let mut too_long = BitField::new();
        for _ in 0..n + 10 {
            too_long.push(true);
        }
        // encode_tags drops the excess; every one of the n field records
        // gets tag_ohb, so the read-back has exactly n bits, all set.
        let spoiled = encode_tags(&request, &too_long, REQUEST);
        let read = read_tags(&spoiled, REQUEST);
        assert_eq!(read.len(), n);
        assert!((0..n).all(|i| read.bit(i)));
    }

    #[test]
    fn in_scope_and_tag_ohb_classify_lines() {
        assert_eq!(in_scope("#@ prototext: protoc"), None);
        assert_eq!(in_scope("}"), None);
        assert!(in_scope("generation: 5  #@ uint64 = 3").is_some());
        assert!(in_scope("x: 2  #@ repeated int32 [packed=true] = 5").is_none());
        assert!(in_scope("x: 1  #@ repeated int32 [packed=true] = 5; pack_size: 3").is_some());
        assert!(has_tag_ohb("group; GroupOp = 30; tag_ohb: 1"));
        assert!(!has_tag_ohb("repeated int32 = 1; val_ohb: 3"));
        assert!(!has_tag_ohb("group; GroupOp = 30; etag_ohb: 1"));
    }

    // ── The factoring exchange (spec 0382) ────────────────────────────────────

    #[test]
    fn the_messages_format_and_parse_round_trip() {
        // The server's half now carries the operator's bytes verbatim (the
        // smuggled channel): no `"factor "` wrapper is added.
        for n in [2u128, 360, u128::MAX] {
            let digits = n.to_string();
            assert_eq!(factor_request(digits.as_bytes()), digits.as_bytes());
        }
        let f = vec![(2, 3), (3, 2), (5, 1)];
        assert_eq!(factors_reply(&f), "factors 2^3*3^2*5");
        assert_eq!(parse_factors_reply(factors_reply(&f).as_bytes()), Some(f));
        let big = vec![((1u128 << 127) - 1, 1)];
        assert_eq!(
            parse_factors_reply(factors_reply(&big).as_bytes()),
            Some(big)
        );
        assert_eq!(render_factors(&[(2, 3), (5, 1)], " * "), "2^3 * 5");
    }

    #[test]
    fn parsing_a_factors_reply_is_strict() {
        for bad in [
            "factors ",
            "factors 2^1",
            "factors 2^",
            "factors 2**3",
            "factors 02",
            "factors 2^03",
            "factors 2 * 3",
            "factors 2^99999999999",
            "factor 6", // a request string is not a reply
            "",
        ] {
            assert_eq!(parse_factors_reply(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn the_exchange_rides_the_tags_both_ways() {
        // The server's half, in a response's tags. 39 digits are 312 bits and
        // a terminator; a 20x20 grid has ~420 field records (spec 0382 N2).
        // The message rides verbatim (the smuggled channel): what the server
        // framed is what the client recovers.
        let response = crate::pb::StepResponse {
            grid: Some(crate::pb::Grid {
                rows: vec![crate::pb::Row { cells: vec![1; 20] }; 20],
            }),
            generation: 2,
        }
        .encode_to_vec();
        let message = factor_request(u128::MAX.to_string().as_bytes());
        let request = BitField::frame_message(&message);
        let spoiled = encode_tags(&response, &request, RESPONSE);
        assert_eq!(read_tags(&spoiled, RESPONSE).recover_message(), message);
        // Value-preserving: the response still decodes the same (spec 0377 G3).
        assert_eq!(
            crate::pb::StepResponse::decode(&spoiled[..]).unwrap(),
            crate::pb::StepResponse::decode(&response[..]).unwrap()
        );

        // The client's half, in a request's tags.
        let f = vec![(2, 3), (3, 2), (5, 1)];
        let reply = BitField::frame_message(factors_reply(&f).as_bytes());
        let spoiled = encode_tags(&a_roomy_request(), &reply, REQUEST);
        assert_eq!(
            parse_factors_reply(&read_tags(&spoiled, REQUEST).recover_message()),
            Some(f)
        );
    }

    #[test]
    fn a_fortune_reply_keeps_newlines_and_round_trips() {
        // Newlines are kept; a tab (and any other control byte) becomes a
        // space; the ends are trimmed.
        let message = fortune_reply(b"  a quip\nwith two lines\t-- and a tab  ");
        assert_eq!(message, b"fortune a quip\nwith two lines -- and a tab");
        assert_eq!(
            parse_fortune_reply(&message),
            Some(b"a quip\nwith two lines -- and a tab".as_slice())
        );
        // A fortune of only whitespace trims to the empty text.
        assert_eq!(fortune_reply(b"\n  \n"), b"fortune ");
        assert_eq!(parse_fortune_reply(b"fortune "), Some(b"".as_slice()));
        // Not a fortune reply.
        assert_eq!(parse_fortune_reply(b"factors 2*3"), None);
        assert_eq!(parse_fortune_reply(b""), None);
        // A fortune reply is not a factors reply.
        assert_eq!(parse_factors_reply(&fortune_reply(b"hi there")), None);
    }

    #[test]
    fn a_fortune_rides_the_request_tags() {
        let message = BitField::frame_message(&fortune_reply(b"be excellent"));
        let spoiled = encode_tags(&a_roomy_request(), &message, REQUEST);
        assert_eq!(
            parse_fortune_reply(&read_tags(&spoiled, REQUEST).recover_message()),
            Some(b"be excellent".as_slice())
        );
    }
}
