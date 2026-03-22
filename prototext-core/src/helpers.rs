// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

// ── Wire-type constants ───────────────────────────────────────────────────────

pub const WT_VARINT: u32 = 0;
pub const WT_I64: u32 = 1;
pub const WT_LEN: u32 = 2;
pub const WT_START_GROUP: u32 = 3;
pub const WT_END_GROUP: u32 = 4;
pub const WT_I32: u32 = 5;

// ── Varint parser result ──────────────────────────────────────────────────────

/// Result of parsing one protobuf varint from a byte slice.
///
/// Mirrors the Python `Varint` class in `lib/varint.py`.
///
/// Exactly one of `varint` or `varint_gar` is `Some`:
/// * `varint_gar` is `Some` when the varint is truncated (buffer ends before
///   the terminator byte) or exceeds 64 bits.
/// * `varint` is `Some` for a successfully decoded varint.
/// * `varint_ohb` counts trailing non-canonical (overhung) bytes: set when
///   the terminating byte is `0x00` preceded by one or more `0x80` bytes.
#[derive(Debug)]
pub struct VarintResult {
    /// Byte position immediately after the parsed varint.
    pub next_pos: usize,
    /// `Some(raw_bytes)` when the varint is garbage (truncated / too large).
    pub varint_gar: Option<Vec<u8>>,
    /// The decoded varint value (valid only when `varint_gar` is `None`).
    pub varint: Option<u64>,
    /// Number of non-canonical overhang bytes (valid only when `varint_gar` is `None`).
    pub varint_ohb: Option<u64>,
}

/// Parse one protobuf varint starting at `start` in `buf`.
///
/// Mirrors `Varint.__init__` in `lib/varint.py`.
///
/// OPT-3: #[inline] allows the compiler to merge this function into the
/// parse_wiretag and decoder hot loops, enabling intra-procedural optimizations
/// (constant-fold the shift sequence, avoid call overhead).  perf showed
/// parse_varint at 4.33% and parse_wiretag at 10.49% of Path A samples.
#[inline]
pub fn parse_varint(buf: &[u8], start: usize) -> VarintResult {
    let buflen = buf.len();
    assert!(start <= buflen);

    if start == buflen {
        // Empty buffer at this position → garbage (empty)
        return VarintResult {
            next_pos: start,
            varint_gar: Some(vec![]),
            varint: None,
            varint_ohb: None,
        };
    }

    let mut v: u64 = 0;
    let mut shift: u32 = 0;
    let mut pos = start;
    let mut too_big = false;

    loop {
        if pos >= buflen {
            // Truncated varint — return rest of buffer as garbage (matches Python)
            return VarintResult {
                next_pos: buflen,
                varint_gar: Some(buf[start..].to_vec()),
                varint: None,
                varint_ohb: None,
            };
        }
        let b = buf[pos];
        pos += 1;

        let bits = (b & 0x7f) as u64;
        if shift < 64 {
            // shift == 63: the 10th byte.  Only bit 0 is valid for a u64;
            // bits ≥ 2 would produce a value ≥ 2^64.
            if shift == 63 && bits > 1 {
                too_big = true;
            } else {
                v |= bits << shift;
            }
        } else {
            // ≥ 11th byte: any set bit overflows u64.
            if bits != 0 {
                too_big = true;
            }
        }
        shift += 7;

        if b & 0x80 == 0 {
            break; // terminator found
        }

        if shift > 70 {
            // Absurdly long varint (> 10 bytes): consume continuation bytes and
            // flag as too_big.
            while pos < buflen {
                let b2 = buf[pos];
                pos += 1;
                if (b2 & 0x7f) != 0 {
                    too_big = true;
                }
                if b2 & 0x80 == 0 {
                    break;
                }
            }
            break;
        }
    }

    if too_big {
        // Python sets pos = buflen before its else-clause fires, so varint_gar
        // always contains buf[start..] (rest of buffer) on overflow.  Matching
        // that behaviour ensures identical INVALID_VARINT content.
        return VarintResult {
            next_pos: buflen,
            varint_gar: Some(buf[start..].to_vec()),
            varint: None,
            varint_ohb: None,
        };
    }

    // The byte at buf[pos-1] is the terminator (the byte that ended the varint).
    // Use it directly instead of tracking `last_b` across loop iterations.
    let last_b = buf[pos - 1];

    // Check for overhung bytes: terminator is 0x00 preceded by ≥1 × 0x80
    let ohb = if last_b == 0x00 && pos > start + 1 {
        // Count trailing 0x80 bytes before the 0x00 terminator
        let mut count: u64 = 1;
        let mut p = pos - 2; // byte before the 0x00
        while p > start && buf[p] == 0x80 {
            count += 1;
            p -= 1;
        }
        Some(count)
    } else {
        None
    };

    VarintResult {
        next_pos: pos,
        varint_gar: None,
        varint: Some(v),
        varint_ohb: ohb,
    }
}

/// Encode a varint value (with optional overhang bytes) back to bytes.
///
/// Mirrors `Varint.__bytes__` in `lib/varint.py`.
pub fn encode_varint_bytes(value: u64, ohb: Option<u64>) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint_ohb(value, ohb, &mut out);
    out
}

/// Append a varint encoding of `value` (with optional overhang bytes) directly
/// into `out`, with no allocation.
///
/// OPT-2: This is the in-place replacement for `encode_varint_bytes`.  The old
/// function allocated a fresh Vec<u8> per call (~18 ns each; 6× slower than
/// appending to an existing Vec).  Callers that already have a target buffer
/// should call this instead, eliminating the allocate-copy-free cycle that
/// showed up as 21% memmove + 11% malloc/free in the perf profile of Path A.
#[inline]
pub fn write_varint_ohb(value: u64, ohb: Option<u64>, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            break;
        }
    }
    if let Some(count) = ohb {
        if count > 0 {
            *out.last_mut().unwrap() |= 0x80; // make last byte a continuation
            for _ in 0..count - 1 {
                out.push(0x80);
            }
            out.push(0x00); // final terminator
        }
    }
}

// ── Wiretag parser result ─────────────────────────────────────────────────────

/// Result of parsing one protobuf wire tag (field number + wire type).
///
/// Mirrors the Python `Wiretag` class in `lib/wiretag.py`.
///
/// Exactly one of `wtag_gar` or `wtype` is valid:
/// * `wtag_gar` is `Some` when the wire type is > 5 (invalid) or the
///   field-number varint is truncated / too large.
/// * Otherwise `wtype` holds the wire type (0–5) and `wfield` the field number.
#[derive(Debug, Clone)]
pub struct WiretagResult {
    pub next_pos: usize,
    /// Raw bytes when the tag is garbage.
    pub wtag_gar: Option<Vec<u8>>,
    /// Wire type (0–5); valid only when `wtag_gar` is `None`.
    pub wtype: Option<u32>,
    /// Field number; valid only when `wtag_gar` is `None`.
    pub wfield: Option<u64>,
    /// Overhang count in the field-number varint.
    pub wfield_ohb: Option<u64>,
    /// `true` when field number is 0 or ≥ 2²⁹.
    pub wfield_oor: Option<bool>,
}

/// Parse one wire tag starting at `start` in `buf`.
///
/// Mirrors `Wiretag.__init__` in `lib/wiretag.py`.
///
/// OPT-3: #[inline] pairs with #[inline] on parse_varint so the compiler can
/// fold both into the decoder.rs hot loop without separate call frames.
#[inline]
pub fn parse_wiretag(buf: &[u8], start: usize) -> WiretagResult {
    let buflen = buf.len();
    assert!(start < buflen, "parse_wiretag called at end of buffer");

    let first_byte = buf[start];
    let wtype = (first_byte & 0x07) as u32;

    if wtype > 5 {
        // Invalid wire type: consume rest of buffer as garbage
        return WiretagResult {
            next_pos: buflen,
            wtag_gar: Some(buf[start..].to_vec()),
            wtype: None,
            wfield: None,
            wfield_ohb: None,
            wfield_oor: None,
        };
    }

    // The field number occupies bits 3.. of the varint.
    // Parse the whole tag as a varint, then extract field number from bits 3+.
    let vr = parse_varint(buf, start);

    if let Some(gar) = vr.varint_gar {
        // Truncated or too-large tag varint
        return WiretagResult {
            next_pos: vr.next_pos,
            wtag_gar: Some(gar),
            wtype: None,
            wfield: None,
            wfield_ohb: None,
            wfield_oor: None,
        };
    }

    let raw = vr.varint.unwrap();
    let field_number = raw >> 3;
    let ohb = vr.varint_ohb;
    let oor = if field_number == 0 || field_number >= (1 << 29) {
        Some(true)
    } else {
        None
    };

    WiretagResult {
        next_pos: vr.next_pos,
        wtag_gar: None,
        wtype: Some(wtype),
        wfield: Some(field_number),
        wfield_ohb: ohb,
        wfield_oor: oor,
    }
}

// ── Numeric type codecs ───────────────────────────────────────────────────────
// Mirror prototext/helpers.py exactly.  All functions are trivial but must
// be correct — errors here silently break round-trip fidelity.

/// Decode varint as int64 (two's complement).
#[inline]
pub fn decode_int64(v: u64) -> i64 {
    v as i64
}

/// Decode varint as int32 (two's complement, low 32 bits).
#[inline]
pub fn decode_int32(v: u64) -> i32 {
    (v as u32) as i32
}

/// Decode varint as uint32.
#[inline]
pub fn decode_uint32(v: u64) -> u32 {
    v as u32
}

/// Decode varint as uint64.
#[inline]
pub fn decode_uint64(v: u64) -> u64 {
    v
}

/// Decode varint as bool (0 → false, 1 → true).
#[inline]
pub fn decode_bool(v: u64) -> bool {
    v != 0
}

/// Decode varint as sint32 (zig-zag).
#[inline]
pub fn decode_sint32(v: u64) -> i32 {
    let n = v as u32;
    ((n >> 1) as i32) ^ -((n & 1) as i32)
}

/// Decode varint as sint64 (zig-zag).
#[inline]
pub fn decode_sint64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Decode 4 little-endian bytes as fixed32 (uint32).
#[inline]
pub fn decode_fixed32(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[..4].try_into().unwrap())
}

/// Decode 4 little-endian bytes as sfixed32 (int32).
#[inline]
pub fn decode_sfixed32(data: &[u8]) -> i32 {
    i32::from_le_bytes(data[..4].try_into().unwrap())
}

/// Decode 4 little-endian bytes as f32.
#[inline]
pub fn decode_float(data: &[u8]) -> f32 {
    f32::from_le_bytes(data[..4].try_into().unwrap())
}

/// Decode 8 little-endian bytes as fixed64 (uint64).
#[inline]
pub fn decode_fixed64(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[..8].try_into().unwrap())
}

/// Decode 8 little-endian bytes as sfixed64 (int64).
#[inline]
pub fn decode_sfixed64(data: &[u8]) -> i64 {
    i64::from_le_bytes(data[..8].try_into().unwrap())
}

/// Decode 8 little-endian bytes as f64.
#[inline]
pub fn decode_double(data: &[u8]) -> f64 {
    f64::from_le_bytes(data[..8].try_into().unwrap())
}

// ── Wire-encoding helpers (used by pt_codec.rs) ───────────────────────────────

/// Append a raw varint encoding of `value` to `buf`.
#[inline]
pub fn write_varint(value: u64, buf: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            buf.push(b | 0x80);
        } else {
            buf.push(b);
            break;
        }
    }
}

/// Append a field tag (wire_type 0–5) to `buf`.
#[inline]
pub fn write_tag(field_number: u32, wire_type: u32, buf: &mut Vec<u8>) {
    write_varint(((field_number as u64) << 3) | (wire_type as u64), buf);
}

/// Append a VARINT field to `buf`.
#[inline]
pub fn write_varint_field(field_number: u32, value: u64, buf: &mut Vec<u8>) {
    write_tag(field_number, WT_VARINT, buf);
    write_varint(value, buf);
}

/// Append a bool field (VARINT) to `buf` — only written when `true`.
#[inline]
pub fn write_bool_field(field_number: u32, value: bool, buf: &mut Vec<u8>) {
    if value {
        write_tag(field_number, WT_VARINT, buf);
        buf.push(1u8);
    }
}

/// Append an optional VARINT field to `buf` — only written when `Some`.
#[inline]
pub fn write_opt_varint_field(field_number: u32, value: Option<u64>, buf: &mut Vec<u8>) {
    if let Some(v) = value {
        write_varint_field(field_number, v, buf);
    }
}

/// Append a LEN-delimited field to `buf`.
#[inline]
pub fn write_len_field(field_number: u32, data: &[u8], buf: &mut Vec<u8>) {
    write_tag(field_number, WT_LEN, buf);
    write_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// Append a fixed-32 field to `buf`.
pub fn write_fixed32_field(field_number: u32, value: u32, buf: &mut Vec<u8>) {
    write_tag(field_number, WT_I32, buf);
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append a fixed-64 field to `buf`.
pub fn write_fixed64_field(field_number: u32, value: u64, buf: &mut Vec<u8>) {
    write_tag(field_number, WT_I64, buf);
    buf.extend_from_slice(&value.to_le_bytes());
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── varint round-trips ────────────────────────────────────────────────────

    #[test]
    fn varint_zero() {
        let buf = [0x00u8];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(0));
        assert_eq!(r.varint_ohb, None);
        assert_eq!(r.next_pos, 1);
    }

    #[test]
    fn varint_one_byte() {
        let buf = [0x01u8];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(1));
        assert_eq!(r.next_pos, 1);
    }

    #[test]
    fn varint_150() {
        // 150 = 0x96 0x01
        let buf = [0x96u8, 0x01];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(150));
        assert_eq!(r.next_pos, 2);
        assert_eq!(r.varint_ohb, None);
    }

    #[test]
    fn varint_max_u64() {
        // max u64: 10 bytes of 0xFF followed by 0x01
        let buf = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(u64::MAX));
        assert_eq!(r.next_pos, 10);
    }

    #[test]
    fn varint_truncated() {
        // Continuation byte with no terminator
        let buf = [0x80u8, 0x80];
        let r = parse_varint(&buf, 0);
        assert!(r.varint_gar.is_some());
        assert!(r.varint.is_none());
    }

    #[test]
    fn varint_empty_at_end() {
        let buf = [0x01u8];
        let r = parse_varint(&buf, 1); // start == buflen
        assert!(r.varint_gar.is_some());
        assert_eq!(r.varint_gar.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn varint_overhang_one() {
        // 0x00 encoded non-canonically as 0x80 0x00
        let buf = [0x80u8, 0x00];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(0));
        assert_eq!(r.varint_ohb, Some(1));
    }

    #[test]
    fn varint_overhang_two() {
        // 0x00 encoded as 0x80 0x80 0x00  (2 overhang bytes)
        let buf = [0x80u8, 0x80, 0x00];
        let r = parse_varint(&buf, 0);
        assert_eq!(r.varint, Some(0));
        assert_eq!(r.varint_ohb, Some(2));
    }

    #[test]
    fn varint_encode_with_overhang() {
        let bytes = encode_varint_bytes(0, Some(1));
        assert_eq!(bytes, vec![0x80, 0x00]);

        let bytes2 = encode_varint_bytes(0, Some(2));
        assert_eq!(bytes2, vec![0x80, 0x80, 0x00]);

        let bytes3 = encode_varint_bytes(150, None);
        assert_eq!(bytes3, vec![0x96, 0x01]);
    }

    #[test]
    fn varint_encode_roundtrip() {
        for val in [0u64, 1, 127, 128, 300, 16383, 16384, u64::MAX] {
            let encoded = encode_varint_bytes(val, None);
            let r = parse_varint(&encoded, 0);
            assert_eq!(r.varint, Some(val), "roundtrip failed for {val}");
            assert_eq!(r.next_pos, encoded.len());
        }
    }

    // ── wiretag ──────────────────────────────────────────────────────────────

    #[test]
    fn wiretag_field1_varint() {
        // tag for field 1, wire type 0: (1 << 3) | 0 = 0x08
        let buf = [0x08u8];
        let r = parse_wiretag(&buf, 0);
        assert_eq!(r.wtype, Some(0));
        assert_eq!(r.wfield, Some(1));
        assert_eq!(r.wfield_ohb, None);
        assert_eq!(r.wfield_oor, None);
    }

    #[test]
    fn wiretag_invalid_wire_type() {
        // wire type 6 is invalid
        let buf = [0x06u8, 0x00, 0x01];
        let r = parse_wiretag(&buf, 0);
        assert!(r.wtag_gar.is_some());
        assert!(r.wtype.is_none());
    }

    #[test]
    fn wiretag_field_number_zero_is_oor() {
        // field number 0: wire type 0, field 0 → (0 << 3) | 0 = 0x00
        // but parse_wiretag asserts start < buflen, so use a buffer with content
        let buf = [0x00u8]; // tag byte = 0 → wire_type=0, field=0
        let r = parse_wiretag(&buf, 0);
        assert_eq!(r.wfield, Some(0));
        assert_eq!(r.wfield_oor, Some(true));
    }

    #[test]
    fn wiretag_overhung() {
        // Field 1, wire type 0 encoded non-canonically: (0x08) as 0x88 0x00
        let buf = [0x88u8, 0x00];
        let r = parse_wiretag(&buf, 0);
        assert_eq!(r.wtype, Some(0));
        assert_eq!(r.wfield, Some(1));
        assert_eq!(r.wfield_ohb, Some(1));
    }

    // ── numeric codecs ────────────────────────────────────────────────────────

    #[test]
    fn int32_negative() {
        // -1 as int32 is stored as 0xFFFFFFFF in a varint
        assert_eq!(decode_int32(0xFFFFFFFF), -1i32);
    }

    #[test]
    fn int64_negative() {
        assert_eq!(decode_int64(u64::MAX), -1i64);
    }

    #[test]
    fn sint32_roundtrip() {
        for v in [-1i32, 0, 1, -2, 2, i32::MIN, i32::MAX] {
            let encoded = if v >= 0 {
                ((v as u32) << 1) as u64
            } else {
                ((!v as u32) * 2 + 1) as u64
            };
            assert_eq!(decode_sint32(encoded), v, "sint32 roundtrip for {v}");
        }
    }

    #[test]
    fn sint64_roundtrip() {
        for v in [-1i64, 0, 1, -2, 2, i64::MIN, i64::MAX] {
            let encoded = if v >= 0 {
                (v as u64) << 1
            } else {
                ((!v as u64) << 1) | 1
            };
            assert_eq!(decode_sint64(encoded), v, "sint64 roundtrip for {v}");
        }
    }

    #[test]
    fn fixed32_little_endian() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        assert_eq!(decode_fixed32(&data), 1u32);
        let data2 = [0xFFu8, 0xFF, 0xFF, 0xFF];
        assert_eq!(decode_fixed32(&data2), u32::MAX);
    }

    #[test]
    fn fixed64_little_endian() {
        let data = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_fixed64(&data), 1u64);
    }

    #[test]
    fn double_roundtrip() {
        let val = std::f64::consts::PI;
        let data = val.to_le_bytes();
        assert_eq!(decode_double(&data), val);
    }

    #[test]
    fn float_roundtrip() {
        let val = 1.5f32;
        let data = val.to_le_bytes();
        assert_eq!(decode_float(&data), val);
    }

    #[test]
    fn write_varint_field_roundtrip() {
        let mut buf = Vec::new();
        write_varint_field(1, 300, &mut buf);
        // tag: (1<<3)|0 = 0x08; value 300 = 0xAC 0x02
        assert_eq!(buf, vec![0x08, 0xAC, 0x02]);
    }

    #[test]
    fn write_len_field_roundtrip() {
        let mut buf = Vec::new();
        write_len_field(2, b"hi", &mut buf);
        // tag: (2<<3)|2 = 0x12; length: 0x02; data: 0x68 0x69
        assert_eq!(buf, vec![0x12, 0x02, 0x68, 0x69]);
    }
}
