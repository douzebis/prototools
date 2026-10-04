// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The `--log-file` traffic log (spec 0386): a protobuf of the requests and
//! responses the server saw, appended entry by entry, and kept **truncated on
//! disk by construction** so a Ctrl-C always leaves a partial protobuf.
//!
//! The log message is `LogFile { repeated Request request = 1; repeated
//! Response response = 2; }` (spec 0386 S2). Each step appends two entries — a
//! `Request`, then a `Response` — each framed as `tag || length-prefix ||
//! body`. Concatenated, the entries are a valid encoding of the growing
//! `LogFile`; the server never re-encodes the whole message, it only appends
//! (spec 0386 S3).
//!
//! The write discipline (spec 0386 S3, G2): the bytes on disk always end with a
//! complete tag + length prefix whose body is still **incomplete** — a
//! truncated protobuf, guaranteed, so `protoc --decode_raw` always chokes.
//! Each step flushes the previous step's held-back tail, then this step's
//! `Request` in full and the `Response`'s tag + length + all but its last body
//! byte, and holds that last byte in `carry`. On Ctrl-C the process dies with
//! `carry` unwritten: dropping it *is* the truncation (no signal handler, no
//! flush-on-exit).

use life::pb::log::{Request, Response};
use prost::Message;
use std::io::Write;

/// The LogFile field numbers (spec 0386 S2).
const REQUEST_FIELD: u64 = 1;
const RESPONSE_FIELD: u64 = 2;
/// Protobuf wire type 2 (length-delimited): a `repeated` message field.
const WIRE_LEN: u64 = 2;

/// An open traffic log and the single body byte held back from disk (spec 0386
/// S3). `carry` is the last body byte of the most recent entry written, kept
/// off disk so the file always ends mid-body.
pub struct Log {
    file: std::fs::File,
    /// The bytes not yet on disk: the tail of the latest entry whose body is
    /// deliberately left incomplete. Never empty after the first `record`
    /// (the invariant), so the file on disk is always a truncated protobuf.
    carry: Vec<u8>,
}

impl Log {
    /// Open `path` for writing, truncating any existing file (spec 0386 S1).
    pub fn create(path: &str) -> std::io::Result<Self> {
        Ok(Log {
            file: std::fs::File::create(path)?,
            carry: Vec::new(),
        })
    }

    /// Append a `Request` and a `Response` entry for one step, keeping the
    /// on-disk file truncated (spec 0386 S3). `request` is the `Request`
    /// leaf, `response` the `Response` leaf (shaped by spec 0387); the field
    /// numbers wrap them into the `LogFile`.
    ///
    /// The flush order each step: the previous step's held-back byte, then this
    /// step's full `Request` entry, then the `Response` entry minus its last
    /// body byte, which becomes the new `carry`.
    pub fn record(&mut self, request: &Request, response: &Response) -> std::io::Result<()> {
        let request_entry = framed_entry(REQUEST_FIELD, &request.encode_to_vec());
        let response_entry = framed_entry(RESPONSE_FIELD, &response.encode_to_vec());

        // Write the previous carry, the whole Request entry, and the Response
        // entry up to (but not including) its final body byte. The Response
        // body is always at least one byte (its wrapped StepResponse is several
        // bytes, spec 0387), so there is always a byte to hold back.
        let (head, last) = response_entry.split_at(response_entry.len() - 1);
        let mut to_flush = std::mem::take(&mut self.carry);
        to_flush.extend_from_slice(&request_entry);
        to_flush.extend_from_slice(head);
        self.file.write_all(&to_flush)?;
        self.file.flush()?;
        self.carry = last.to_vec();
        Ok(())
    }
}

/// A length-delimited field entry: `tag || length-prefix || body`, where the
/// tag packs `field_number` with wire type 2 (spec 0386 S2).
fn framed_entry(field_number: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    put_varint(&mut out, (field_number << 3) | WIRE_LEN); // the tag
    put_varint(&mut out, body.len() as u64); // the length prefix
    out.extend_from_slice(body);
    out
}

/// Append `value` as a base-128 varint.
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Response` whose body is several bytes (a wrapped StepResponse plus
    /// the distinguishing fields), the smallest realistic entry.
    fn a_response() -> Response {
        Response {
            step: Some(life::pb::StepResponse {
                grid: Some(life::pb::Grid {
                    rows: vec![life::pb::Row {
                        cells: vec![life::pb::CellState::Alive as i32],
                    }],
                }),
                generation: 1,
            }),
            latency_us: 42,
            output: b"hi".to_vec(),
        }
    }

    fn a_request() -> Request {
        Request {
            step: Some(life::pb::StepRequest {
                grid: Some(life::pb::Grid {
                    rows: vec![life::pb::Row {
                        cells: vec![life::pb::CellState::Alive as i32],
                    }],
                }),
                rules: None,
                generation: 1,
            }),
            command: "whoami".to_string(),
            generation: 1,
        }
    }

    /// The bytes on disk after `steps` record calls (the carry stays off disk).
    fn on_disk(steps: usize) -> Vec<u8> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("life-log-test-{}.bin", std::process::id()));
        let path = path.to_str().unwrap();
        let mut log = Log::create(path).unwrap();
        for _ in 0..steps {
            log.record(&a_request(), &a_response()).unwrap();
        }
        let bytes = std::fs::read(path).unwrap();
        std::fs::remove_file(path).ok();
        bytes
    }

    /// The (field number, wire type) pairs present in `bytes`, in order.
    fn shape(bytes: &[u8]) -> Vec<(u64, u64)> {
        let mut pairs = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let (tag, used) = read_varint(&bytes[i..]);
            i += used;
            let (field, wire) = (tag >> 3, tag & 0x7);
            pairs.push((field, wire));
            match wire {
                0 => i += read_varint(&bytes[i..]).1, // varint
                2 => {
                    let (len, u) = read_varint(&bytes[i..]); // length-delimited
                    i += u + len as usize;
                }
                5 => i += 4, // i32
                1 => i += 8, // i64
                _ => break,
            }
        }
        pairs
    }

    /// Spec 0387 test plan 1 / G1: Request and Response have unequal
    /// (field number, wire type) multisets — they differ at fields 2 and 3 —
    /// so the scorer can tell them apart. The shared pair is only (1, LEN).
    #[test]
    fn request_and_response_have_different_field_shapes() {
        // Populate every field so each is present on the wire.
        let request = a_request();
        let response = a_response();
        let mut rq = shape(&request.encode_to_vec());
        let mut rs = shape(&response.encode_to_vec());
        rq.sort_unstable();
        rs.sort_unstable();
        // WIRE_LEN = 2 (length-delimited), 0 = varint.
        assert_eq!(rq, vec![(1, 2), (2, 2), (3, 0)], "Request shape");
        assert_eq!(rs, vec![(1, 2), (2, 0), (3, 2)], "Response shape");
        assert_ne!(rq, rs, "the two shapes must differ (spec 0387 G1)");
        // They share only (1, LEN); fields 2 and 3 each swap varint for LEN.
        let shared: Vec<_> = rq.iter().filter(|p| rs.contains(p)).collect();
        assert_eq!(shared, vec![&(1, 2)], "only field 1 is shared");
    }

    #[test]
    fn put_varint_matches_protobuf() {
        let mut v = Vec::new();
        put_varint(&mut v, 0);
        assert_eq!(v, [0x00]);
        let mut v = Vec::new();
        put_varint(&mut v, 300);
        assert_eq!(v, [0xac, 0x02]); // 300 = 0b1_0010_1100
    }

    #[test]
    fn the_entry_is_tag_length_body() {
        let entry = framed_entry(REQUEST_FIELD, b"abc");
        // tag = (1<<3)|2 = 0x0a, length = 3, then the body.
        assert_eq!(entry, [0x0a, 0x03, b'a', b'b', b'c']);
        let entry = framed_entry(RESPONSE_FIELD, b"xy");
        assert_eq!(entry, [0x12, 0x02, b'x', b'y']); // tag = (2<<3)|2 = 0x12
    }

    /// Spec 0386 G2/S3, test plan 2: after any number of steps, the on-disk
    /// bytes always end with a length prefix promising more body than follows,
    /// so `--decode_raw` would fail. The invariant check is structural: the
    /// last Response entry on disk is short by exactly the held-back byte.
    #[test]
    fn the_on_disk_file_is_always_a_truncated_protobuf() {
        for steps in [1usize, 2, 3, 10] {
            let bytes = on_disk(steps);
            // Re-derive the full stream (what *would* be on disk with the carry)
            // and confirm the disk bytes are exactly one byte short of it.
            let full = full_stream(steps);
            assert_eq!(
                bytes.len(),
                full.len() - 1,
                "steps={steps}: the last body byte is held back"
            );
            assert_eq!(bytes, &full[..full.len() - 1], "steps={steps}");
            // And the truncation falls inside the final Response's body: the
            // last entry's declared length exceeds the body bytes that follow.
            assert!(
                last_entry_body_is_short(&bytes),
                "steps={steps}: the tail entry's length prefix overshoots"
            );
        }
    }

    /// The whole byte stream for `steps` steps, carry included (what a clean,
    /// non-truncating writer would have produced).
    fn full_stream(steps: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..steps {
            out.extend_from_slice(&framed_entry(REQUEST_FIELD, &a_request().encode_to_vec()));
            out.extend_from_slice(&framed_entry(RESPONSE_FIELD, &a_response().encode_to_vec()));
        }
        out
    }

    /// Walk the length-delimited entries of `bytes`; return true if the final
    /// entry's declared length runs past the end of the buffer (a truncation).
    fn last_entry_body_is_short(bytes: &[u8]) -> bool {
        let mut i = 0;
        loop {
            if i >= bytes.len() {
                return false; // ended cleanly on an entry boundary
            }
            // tag (one byte for fields 1/2), then a length varint.
            i += 1;
            let (len, used) = read_varint(&bytes[i..]);
            i += used;
            let body_end = i + len as usize;
            if body_end > bytes.len() {
                return true; // the body is cut short: a truncated protobuf
            }
            i = body_end;
        }
    }

    fn read_varint(bytes: &[u8]) -> (u64, usize) {
        let mut value = 0u64;
        let mut shift = 0;
        for (n, &b) in bytes.iter().enumerate() {
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return (value, n + 1);
            }
            shift += 7;
        }
        (value, bytes.len())
    }
}
