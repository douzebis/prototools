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

use prototext_core::{parse_schema, render_as_bytes, render_as_text, ParsedSchema, RenderOpts};

/// The request message: what the render decodes against.
const ROOT: &str = "grehack.life.v1.StepRequest";

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

/// The life schema, built once from the embedded descriptor (a lone
/// `FileDescriptorProto`, which a `FileDescriptorSet` wraps for
/// `parse_schema`).
pub fn schema() -> &'static ParsedSchema {
    use prost::Message;
    use prost_types::{FileDescriptorProto, FileDescriptorSet};
    use std::sync::OnceLock;

    static SCHEMA: OnceLock<ParsedSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let file = FileDescriptorProto::decode(crate::DESCRIPTOR)
            .expect("the embedded descriptor is written by build.rs");
        let set = FileDescriptorSet { file: vec![file] }.encode_to_vec();
        parse_schema(&set, ROOT).expect("the life schema holds StepRequest")
    })
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

/// One bit per field record in `request`, in render order: 1 when the field's
/// tag was non-canonical (spec 0377 S3). `request` is the raw request bytes.
pub fn read_tags(request: &[u8]) -> BitField {
    let text = render_as_text(request, schema().root_descriptor().as_ref(), opts())
        .expect("a received request renders");
    let text = String::from_utf8(text).expect("prototext renders UTF-8");

    let mut bits = BitField::new();
    for line in text.lines() {
        if let Some(annotation) = in_scope(line) {
            bits.push(has_tag_ohb(annotation));
        }
    }
    bits
}

/// `request` re-encoded so field record *i*'s tag is non-canonical when
/// `bits.bit(i)` is set (spec 0377 S6). Bits past the field-record count are
/// dropped (N5). Returns the modified wire bytes.
pub fn encode_tags(request: &[u8], bits: &BitField) -> Vec<u8> {
    let text = render_as_text(request, schema().root_descriptor().as_ref(), opts())
        .expect("the request renders");
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
        let text = render_as_text(bytes, schema().root_descriptor().as_ref(), opts()).unwrap();
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
        let bits = read_tags(&bytes);
        assert_eq!(bits.len(), 12);
        assert_eq!(bits.len(), rendered_fields(&bytes));
        assert!(bits.as_bytes().iter().all(|&b| b == 0));
    }

    /// A request with a 5×5 grid: about 36 field records, enough tags to
    /// carry a short message with its terminator.
    fn a_roomy_request() -> Vec<u8> {
        crate::pb::StepRequest {
            grid: Some(crate::pb::Grid {
                rows: vec![
                    crate::pb::Row {
                        cells: vec![1, 0, 1, 0, 1]
                    };
                    5
                ],
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
        let spoiled = encode_tags(&request, &framed);

        // Value-preserving: the spoiled bytes decode to the same StepRequest.
        assert_eq!(
            crate::pb::StepRequest::decode(&spoiled[..]).unwrap(),
            crate::pb::StepRequest::decode(&request[..]).unwrap()
        );
        // And the server's read recovers the message.
        assert_eq!(read_tags(&spoiled).recover_message(), message);
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
        assert_eq!(read_tags(&bytes).as_bytes(), &[0x00, 0x00]);
        assert_eq!(read_tags(&spoiled).as_bytes(), &[0x00, 0b0001_0000]);
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
        let spoiled = encode_tags(&request, &too_long);
        let read = read_tags(&spoiled);
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
}
