// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The `--log-file` traffic log (spec 0386): a protobuf of the messages the
//! server saw, appended entry by entry, and kept **truncated on disk by
//! construction** so a Ctrl-C always leaves a partial protobuf.
//!
//! The log message is `LogFile { repeated Capture capture = 42; }` (spec
//! 0391). Each step appends two captures — the request's, then the
//! response's — each framed as `tag || length-prefix || body`. Concatenated, the entries are a valid encoding of the growing
//! `LogFile`; the server never re-encodes the whole message, it only appends
//! (spec 0386 S3).
//!
//! The write discipline (spec 0386 S3, G2): the bytes on disk always end with a
//! complete tag + length prefix whose body is still **incomplete** — a
//! truncated protobuf, guaranteed, so `protoc --decode_raw` always chokes.
//! Each step flushes the previous step's held-back tail, then this step's
//! request capture in full and the response capture's tag + length + all but
//! its last body byte, and holds that last byte in `carry`. On Ctrl-C the process dies with
//! `carry` unwritten: dropping it *is* the truncation (no signal handler, no
//! flush-on-exit).

use std::io::Write;

/// `LogFile.capture`'s field number (spec 0391 S1): a two-byte tag.
const CAPTURE_FIELD: u64 = 42;
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

    /// Append one step's two encoded captures (spec 0391 S2), keeping the
    /// on-disk file truncated (spec 0386 S3). Both are framed at
    /// `LogFile.capture`.
    ///
    /// The flush order each step: the previous step's held-back byte, then this
    /// step's full request capture, then the response capture minus its last
    /// body byte, which becomes the new `carry`.
    pub fn record(&mut self, request: &[u8], response: &[u8]) -> std::io::Result<()> {
        let request_entry = framed_entry(CAPTURE_FIELD, request);
        let response_entry = framed_entry(CAPTURE_FIELD, response);

        // Write the previous carry, the whole request capture, and the response
        // capture up to (but not including) its final body byte. The response
        // capture's body is always at least one byte (it wraps a StepResponse,
        // spec 0391 S3), so there is always a byte to hold back.
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

/// `Capture`'s field numbers (spec 0391 S1).
const CAPTURE_REQUEST: u64 = 1;
const CAPTURE_RESPONSE: u64 = 2;
const CAPTURE_GENERATION: u64 = 3;
const CAPTURE_CONTRABAND: u64 = 666;
/// Protobuf wire type 0: a varint.
const WIRE_VARINT: u64 = 0;

/// One step's two captures, encoded (spec 0391 S2, S2b): the request's, then
/// the response's. Each carries its own message, that message's generation,
/// and what that message hid, if anything — the command `output` the request
/// brought back, the `command` the response smuggled; empty means nothing was
/// hidden, so `contraband` stays absent.
///
/// The messages are the bytes that crossed the wire, `request_wire` as
/// received and `response_wire` as sent, embedded verbatim as the body of
/// `Capture.request`/`Capture.response`. Re-encoding a decoded message would
/// write it canonically and erase the covert channel's non-canonical
/// varints; the log keeps them (S2b). Fields are written in field-number
/// order, as an encoder of `Capture` would. The output is bytes and
/// `contraband` a protobuf `string`, hence the lossy UTF-8 conversion.
pub fn captures_for_step(
    request_wire: &[u8],
    request_generation: u64,
    response_wire: &[u8],
    response_generation: u64,
    command: &[u8],
    output: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let capture = |field: u64, wire: &[u8], generation: u64, hidden: &[u8]| {
        let mut out = framed_entry(field, wire);
        put_varint(&mut out, (CAPTURE_GENERATION << 3) | WIRE_VARINT);
        put_varint(&mut out, generation);
        if !hidden.is_empty() {
            let text = String::from_utf8_lossy(hidden);
            out.extend_from_slice(&framed_entry(CAPTURE_CONTRABAND, text.as_bytes()));
        }
        out
    };
    (
        capture(CAPTURE_REQUEST, request_wire, request_generation, output),
        capture(
            CAPTURE_RESPONSE,
            response_wire,
            response_generation,
            command,
        ),
    )
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
    use life::pb::log::Capture;
    use prost::Message;

    fn a_request() -> life::pb::StepRequest {
        life::pb::StepRequest {
            grid: Some(life::pb::Grid {
                rows: vec![life::pb::Row {
                    cells: vec![life::pb::CellState::Alive as i32],
                }],
            }),
            rules: None,
            generation: 1,
        }
    }

    fn a_response() -> life::pb::StepResponse {
        life::pb::StepResponse {
            grid: Some(life::pb::Grid {
                rows: vec![life::pb::Row {
                    cells: vec![life::pb::CellState::Alive as i32],
                }],
            }),
            generation: 2,
        }
    }

    /// A step on which the server smuggled `whoami` and the request brought
    /// back an earlier command's output, with canonical wire bytes.
    fn a_step() -> (Vec<u8>, Vec<u8>) {
        captures_for_step(
            &a_request().encode_to_vec(),
            1,
            &a_response().encode_to_vec(),
            2,
            b"whoami",
            b"experiment",
        )
    }

    /// `a_request()`'s bytes with its `generation` (field 3, value 1) written
    /// in two bytes, `0x81 0x00`, instead of one: legal, but not canonical,
    /// like the covert channel's varints (spec 0384).
    fn a_non_canonical_request_wire() -> Vec<u8> {
        let canonical = a_request().encode_to_vec();
        assert!(canonical.ends_with(&[0x18, 0x01]), "generation is last");
        let mut wire = canonical[..canonical.len() - 1].to_vec();
        wire.extend_from_slice(&[0x81, 0x00]);
        wire
    }

    /// The bytes on disk after `steps` record calls (the carry stays off disk).
    fn on_disk(steps: usize) -> Vec<u8> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("life-log-test-{}.bin", std::process::id()));
        let path = path.to_str().unwrap();
        let mut log = Log::create(path).unwrap();
        for _ in 0..steps {
            let (request, response) = a_step();
            log.record(&request, &response).unwrap();
        }
        let bytes = std::fs::read(path).unwrap();
        std::fs::remove_file(path).ok();
        bytes
    }

    /// Spec 0391 test plan 2 (S2): a request capture, then a response
    /// capture; each decodes as a `Capture` holding its own message and
    /// generation, and `contraband` holds only what that message hid.
    #[test]
    fn a_step_logs_a_request_capture_then_a_response_capture() {
        let (request, response) = a_step();
        let request = Capture::decode(&request[..]).unwrap();
        let response = Capture::decode(&response[..]).unwrap();
        assert_eq!(request.request, Some(a_request()));
        assert_eq!(request.response, None);
        assert_eq!(request.generation, Some(1));
        assert_eq!(request.contraband.as_deref(), Some("experiment"));
        assert_eq!(response.request, None);
        assert_eq!(response.response, Some(a_response()));
        assert_eq!(response.generation, Some(2));
        assert_eq!(response.contraband.as_deref(), Some("whoami"));

        // Nothing hidden: no contraband field at all, not an empty one.
        let wire = a_request().encode_to_vec();
        let (request, _) = captures_for_step(&wire, 1, &wire, 1, b"", b"");
        assert_eq!(Capture::decode(&request[..]).unwrap().contraband, None);
        // The output is bytes; a non-UTF-8 one is kept, lossily.
        let (request, _) = captures_for_step(&wire, 1, &wire, 1, b"", b"\xff");
        let request = Capture::decode(&request[..]).unwrap();
        assert_eq!(request.contraband.as_deref(), Some("\u{fffd}"));
    }

    /// Spec 0391 test plan 2b (S2b): the message is embedded as the bytes
    /// that crossed the wire. A non-canonical varint survives in the log,
    /// where re-encoding the decoded message would have written it
    /// canonically; and the capture still decodes under the schema.
    #[test]
    fn a_capture_keeps_the_wire_bytes_verbatim() {
        let wire = a_non_canonical_request_wire();
        assert_ne!(wire, a_request().encode_to_vec());
        let (request, _) = captures_for_step(&wire, 1, b"", 2, b"", b"");
        // tag (1<<3)|2 = 0x0a, one-byte length, then the body verbatim.
        assert_eq!(request[0], 0x0a);
        assert_eq!(usize::from(request[1]), wire.len());
        assert_eq!(&request[2..2 + wire.len()], &wire[..]);
        let decoded = Capture::decode(&request[..]).unwrap();
        assert_eq!(decoded.request, Some(a_request()));
        assert_eq!(decoded.generation, Some(1));
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
        let entry = framed_entry(CAPTURE_FIELD, b"abc");
        // tag = (42<<3)|2 = 338, a two-byte varint (0xd2 0x02); length = 3.
        assert_eq!(entry, [0xd2, 0x02, 0x03, b'a', b'b', b'c']);
    }

    /// Spec 0386 G2/S3, test plan 2: after any number of steps, the on-disk
    /// bytes always end with a length prefix promising more body than follows,
    /// so `--decode_raw` would fail. The invariant check is structural: the
    /// last response capture on disk is short by exactly the held-back byte.
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
            // And the truncation falls inside the final response capture: the
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
            let (request, response) = a_step();
            out.extend_from_slice(&framed_entry(CAPTURE_FIELD, &request));
            out.extend_from_slice(&framed_entry(CAPTURE_FIELD, &response));
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
            // tag (two bytes for field 42), then a length varint.
            i += read_varint(&bytes[i..]).1;
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
