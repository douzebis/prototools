// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Protocraft: a test-only library for constructing protobuf wire bytes
//! programmatically, including non-canonical and malformed encodings.

// ── fixture! / msg_fields! macros ─────────────────────────────────────────────
//
// These macros are test-only (they reference FieldSpec and MessageDescriptor).
// They mirror Python's `with Message(schema=...) as name:` syntax.
// Defined before `pub mod craft_a` so they are in scope within that module.
//
// fixture!(name, descriptor_expr; fields...) expands to:
//   pub fn name() -> Vec<u8> { ... }
//
// msg_fields! field forms:
//   group(field; nested...)   — group body inherits parent descriptor
//   message(field; nested...) — nested message gets field's message_type
//   uint64/int64/uint32/int32/bool_/enum_/sint32/sint64(field, val)
//   fixed64/sfixed64/double_(field, val)
//   bytes_/string(field, val)
//   fixed32/sfixed32/float_(field, val)
//   raw(bytes)

#[cfg(test)]
macro_rules! msg_fields {
    ($m:ident,) => {};

    // group(field; nested...) — body uses the group field's own message_type
    ($m:ident, group($field:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let (_fnum, _gdesc) = super::FieldSpec::resolve($field, $m.desc.as_ref());
        let mut _nm = if let Some(d) = _gdesc {
            Message::with_schema(d)
        } else {
            Message::new()
        };
        msg_fields!(_nm, $($nested)*);
        $m.group(
            Tag { field: _fnum, wire_type: 3, ohb: 0 },
            Tag { field: _fnum, wire_type: 4, ohb: 0 },
            _nm,
        );
        msg_fields!($m, $($rest)*);
    }};

    // group(start_tag => end_tag; nested...) — explicit start/end tags (mismatched numbers or ohb)
    ($m:ident, group($start:expr => $end:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let mut _nm = Message::new();
        msg_fields!(_nm, $($nested)*);
        $m.group($start, $end, _nm);
        msg_fields!($m, $($rest)*);
    }};

    // message(field; nested...) — nested gets field's message_type
    ($m:ident, message($field:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let (_fnum, _mdesc) = super::FieldSpec::resolve($field, $m.desc.as_ref());
        let mut _nm = if let Some(d) = _mdesc {
            Message::with_schema(d)
        } else {
            Message::new()
        };
        msg_fields!(_nm, $($nested)*);
        $m.message(_fnum, _nm);
        msg_fields!($m, $($rest)*);
    }};

    // Scalar field arms.
    // $field is passed directly to the builder (impl IntoFieldTag), so &str,
    // integer literals, and Tag { field, wire_type, ohb } all work transparently.
    ($m:ident, uint64($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.uint64($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, int64($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.int64($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, uint32($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.uint32($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, int32($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.int32($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, bool_($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.bool_($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, enum_($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.enum_($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, sint32($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.sint32($field, $val as i32); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, sint64($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.sint64($field, $val as i64); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, fixed64($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.fixed64($field, $val as u64); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, sfixed64($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.sfixed64($field, $val as i64); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, double_($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.double_($field, $val as f64); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, bytes_($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.bytes_($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, string($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.string($field, $val); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, fixed32($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.fixed32($field, $val as u32); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, sfixed32($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.sfixed32($field, $val as i32); msg_fields!($m, $($rest)*);
    }};
    ($m:ident, float_($field:expr, $val:expr), $($rest:tt)*) => {{
        $m.float_($field, $val as f32); msg_fields!($m, $($rest)*);
    }};

    // raw bytes (verbatim)
    ($m:ident, raw($val:expr), $($rest:tt)*) => {{
        $m.raw($val);
        msg_fields!($m, $($rest)*);
    }};

    // message_with_len(field, len, len_ohb; nested...) — custom/wrong length
    ($m:ident, message_with_len($field:expr, $len:expr, $len_ohb:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let (_fnum, _mdesc) = super::FieldSpec::resolve($field, $m.desc.as_ref());
        let mut _nm = if let Some(d) = _mdesc {
            Message::with_schema(d)
        } else {
            Message::new()
        };
        msg_fields!(_nm, $($nested)*);
        $m.message_with_len(_fnum, $len, $len_ohb, _nm);
        msg_fields!($m, $($rest)*);
    }};

    // string_with_len(field, len; val) — truncated length value
    ($m:ident, string_with_len($field:expr, $len:expr; $val:expr), $($rest:tt)*) => {{
        $m.string_with_len($field, $len, $val);
        msg_fields!($m, $($rest)*);
    }};

    // string_with_len_ohb(field, ohb; val) — overhanging length bytes
    ($m:ident, string_with_len_ohb($field:expr, $ohb:expr; $val:expr), $($rest:tt)*) => {{
        $m.string_with_len_ohb($field, $ohb, $val);
        msg_fields!($m, $($rest)*);
    }};

    // packed_varints(field, [Integer, ...]) — packed varint repeated field
    ($m:ident, packed_varints($field:expr, [$($val:expr),* $(,)?]), $($rest:tt)*) => {{
        $m.packed_varints($field, &[$($val),*]);
        msg_fields!($m, $($rest)*);
    }};

    // packed_sint32(field, [i32, ...]) — packed zigzag sint32
    ($m:ident, packed_sint32($field:expr, [$($val:expr),* $(,)?]), $($rest:tt)*) => {{
        $m.packed_sint32($field, &[$($val),*]);
        msg_fields!($m, $($rest)*);
    }};

    // packed_sint64(field, [i64, ...]) — packed zigzag sint64
    ($m:ident, packed_sint64($field:expr, [$($val:expr),* $(,)?]), $($rest:tt)*) => {{
        $m.packed_sint64($field, &[$($val),*]);
        msg_fields!($m, $($rest)*);
    }};

    // packed_fixed32(field, [expr, ...]) — packed fixed32/float
    ($m:ident, packed_fixed32($field:expr, [$($val:expr),* $(,)?]), $($rest:tt)*) => {{
        $m.packed_fixed32($field, vec![$($val),*]);
        msg_fields!($m, $($rest)*);
    }};

    // packed_fixed32_with_len(field, len, [expr, ...]) — packed fixed32 with truncated length
    ($m:ident, packed_fixed32_with_len($field:expr, $len:expr, [$($val:expr),* $(,)?]), $($rest:tt)*) => {{
        $m.packed_fixed32_with_len($field, $len, vec![$($val),*]);
        msg_fields!($m, $($rest)*);
    }};

    // Trailing-comma-less last entry: re-invoke with a trailing comma appended.
    ($m:ident, $($last:tt)+) => {
        msg_fields!($m, $($last)+,);
    };
}

#[cfg(test)]
macro_rules! fixture {
    ($name:ident, $schema:expr; $($fields:tt)*) => {
        pub fn $name() -> Vec<u8> {
            let mut _m = Message::with_schema($schema);
            msg_fields!(_m, $($fields)*);
            _m.build()
        }
    };
}

pub mod craft_a;

#[cfg(test)]
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};

// ── Core types ────────────────────────────────────────────────────────────────

/// A wire tag with explicit field number, wire type, and optional overhanging bytes.
#[derive(Clone, Copy)]
pub struct Tag {
    pub field: u64,
    pub wire_type: u8,
    pub ohb: u8,
}

impl Tag {
    /// Construct a `Tag` with an explicit name resolved at call time.
    /// Useful for `Tag('fieldName', type=N, ohb=M)` overrides from Python.
    #[cfg(test)]
    pub fn named(name: &str, wire_type: u8, ohb: u8, desc: &MessageDescriptor) -> Self {
        let field = desc
            .get_field_by_name(name)
            .unwrap_or_else(|| panic!("field '{}' not found in descriptor", name))
            .number() as u64;
        Tag {
            field,
            wire_type,
            ohb,
        }
    }
}

/// An integer value with optional overhanging bytes (0 = canonical).
#[derive(Clone, Copy)]
pub struct Integer {
    pub value: u64,
    pub ohb: u8,
}

// ── IntoTag / IntoInteger traits ─────────────────────────────────────────────

/// Low-level tag trait used by `encode_tag` and the tag construction API.
pub trait IntoTag {
    fn into_tag(self, default_wire_type: u8) -> Tag;
}

impl IntoTag for u64 {
    fn into_tag(self, default_wire_type: u8) -> Tag {
        Tag {
            field: self,
            wire_type: default_wire_type,
            ohb: 0,
        }
    }
}

impl IntoTag for u32 {
    fn into_tag(self, default_wire_type: u8) -> Tag {
        Tag {
            field: self as u64,
            wire_type: default_wire_type,
            ohb: 0,
        }
    }
}

impl IntoTag for i32 {
    fn into_tag(self, default_wire_type: u8) -> Tag {
        Tag {
            field: self as u64,
            wire_type: default_wire_type,
            ohb: 0,
        }
    }
}

impl IntoTag for usize {
    fn into_tag(self, default_wire_type: u8) -> Tag {
        Tag {
            field: self as u64,
            wire_type: default_wire_type,
            ohb: 0,
        }
    }
}

impl IntoTag for Tag {
    fn into_tag(self, _default_wire_type: u8) -> Tag {
        self
    }
}

// ── IntoFieldTag: unified field + descriptor resolution for builder methods ───
//
// Builder methods accept `impl IntoFieldTag` so that both numeric/Tag arguments
// and (in test builds) `&str` name-resolved arguments are accepted uniformly.

/// Resolves a field specifier to a `Tag`, using the message descriptor if needed.
///
/// Implemented for:
/// - `Tag`      — passes through wire_type and ohb unchanged.
/// - Integer types — uses the provided `default_wire_type`.
/// - `&str` (test only) — resolves field name against `desc`, uses `default_wire_type`.
pub trait IntoFieldTag {
    fn into_field_tag(
        self,
        default_wire_type: u8,
        #[cfg(test)] desc: Option<&MessageDescriptor>,
        #[cfg(not(test))] _desc: Option<&()>,
    ) -> Tag;
}

macro_rules! impl_into_field_tag_int {
    ($($t:ty),*) => {
        $(
            impl IntoFieldTag for $t {
                fn into_field_tag(
                    self,
                    default_wire_type: u8,
                    #[cfg(test)] _desc: Option<&MessageDescriptor>,
                    #[cfg(not(test))] _desc: Option<&()>,
                ) -> Tag {
                    Tag {
                        field: self as u64,
                        wire_type: default_wire_type,
                        ohb: 0,
                    }
                }
            }
        )*
    };
}

impl_into_field_tag_int!(u64, u32, u16, u8, i64, i32, i16, usize);

impl IntoFieldTag for Tag {
    fn into_field_tag(
        self,
        _default_wire_type: u8,
        #[cfg(test)] _desc: Option<&MessageDescriptor>,
        #[cfg(not(test))] _desc: Option<&()>,
    ) -> Tag {
        self
    }
}

#[cfg(test)]
impl IntoFieldTag for &str {
    fn into_field_tag(
        self,
        default_wire_type: u8,
        desc: Option<&MessageDescriptor>,
        // No non-test variant; this impl only exists under #[cfg(test)]
    ) -> Tag {
        let d = desc.unwrap_or_else(|| {
            panic!(
                "no descriptor bound on message, cannot resolve field '{}'",
                self
            )
        });
        let fd = d
            .get_field_by_name(self)
            .unwrap_or_else(|| panic!("field '{}' not found in descriptor '{}'", self, d.name()));
        Tag {
            field: fd.number() as u64,
            wire_type: default_wire_type,
            ohb: 0,
        }
    }
}

// ── FieldSpec trait ───────────────────────────────────────────────────────────

/// Resolves a field specifier to `(field_number, nested_descriptor)`.
///
/// - `&str` — name lookup against the provided descriptor.
/// - Integer types — pass-through; no lookup needed.
///
/// Used by schema-aware builder methods on `Message`.
#[cfg(test)]
pub trait FieldSpec {
    fn resolve(self, desc: Option<&MessageDescriptor>) -> (u64, Option<MessageDescriptor>);
}

#[cfg(test)]
impl FieldSpec for &str {
    fn resolve(self, desc: Option<&MessageDescriptor>) -> (u64, Option<MessageDescriptor>) {
        let d = desc.unwrap_or_else(|| panic!("no descriptor bound, cannot resolve '{}'", self));
        let fd = d
            .get_field_by_name(self)
            .unwrap_or_else(|| panic!("field '{}' not found in descriptor '{}'", self, d.name()));
        let nested = match fd.kind() {
            Kind::Message(m) => Some(m),
            _ => None,
        };
        (fd.number() as u64, nested)
    }
}

macro_rules! impl_field_spec_int {
    ($($t:ty),*) => {
        $(
            #[cfg(test)]
            impl FieldSpec for $t {
                fn resolve(self, _desc: Option<&MessageDescriptor>) -> (u64, Option<MessageDescriptor>) {
                    (self as u64, None)
                }
            }
        )*
    };
}

impl_field_spec_int!(u64, u32, u16, u8, i64, i32, i16, usize);

#[cfg(test)]
impl FieldSpec for Tag {
    fn resolve(self, _desc: Option<&MessageDescriptor>) -> (u64, Option<MessageDescriptor>) {
        (self.field, None)
    }
}

pub trait IntoInteger {
    fn into_integer(self) -> Integer;
}

impl IntoInteger for u64 {
    fn into_integer(self) -> Integer {
        Integer {
            value: self,
            ohb: 0,
        }
    }
}

impl IntoInteger for i64 {
    fn into_integer(self) -> Integer {
        Integer {
            value: self as u64,
            ohb: 0,
        }
    }
}

impl IntoInteger for u32 {
    fn into_integer(self) -> Integer {
        Integer {
            value: self as u64,
            ohb: 0,
        }
    }
}

impl IntoInteger for i32 {
    fn into_integer(self) -> Integer {
        Integer {
            value: self as i64 as u64,
            ohb: 0,
        }
    }
}

impl IntoInteger for bool {
    fn into_integer(self) -> Integer {
        Integer {
            value: self as u64,
            ohb: 0,
        }
    }
}

impl IntoInteger for Integer {
    fn into_integer(self) -> Integer {
        self
    }
}

// ── Varint encoding ───────────────────────────────────────────────────────────

/// Encode a varint with `ohb` extra continuation bytes appended.
/// ohb=0 produces canonical minimal encoding.
pub fn encode_varint_ohb(value: u64, ohb: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            // Last real byte: set MSB if we still have ohb bytes to emit.
            if ohb == 0 {
                out.push(byte);
                break;
            } else {
                out.push(byte | 0x80);
                // Emit ohb - 1 continuation bytes of 0x80, then one 0x00.
                for _ in 0..(ohb - 1) {
                    out.push(0x80);
                }
                out.push(0x00);
                break;
            }
        } else {
            out.push(byte | 0x80);
        }
    }
    out
}

/// Encode a wire tag: (field_number << 3) | wire_type, as a varint with
/// optional overhanging bytes.
pub fn encode_tag(field: u64, wire_type: u8, ohb: u8) -> Vec<u8> {
    let tag_value = (field << 3) | (wire_type as u64);
    encode_varint_ohb(tag_value, ohb)
}

// ── Scalar encoders ───────────────────────────────────────────────────────────

fn encode_sint32(v: i32) -> u64 {
    ((v << 1) ^ (v >> 31)) as u32 as u64
}

fn encode_sint64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

// ── Descriptor helper functions ───────────────────────────────────────────────

/// Load a `MessageDescriptor` for `SwissArmyKnife` from the compiled schema.
#[cfg(test)]
pub fn knife_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SwissArmyKnife")
        .expect("SwissArmyKnife not found in knife.pb")
}

/// Load a `MessageDescriptor` for `SwissArmyKnifeRq` from the compiled schema.
#[cfg(test)]
pub fn knife_rq_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SwissArmyKnifeRq")
        .expect("SwissArmyKnifeRq not found in knife.pb")
}

/// Load a `MessageDescriptor` for `EnumCollision` from the compiled schema.
#[cfg(test)]
pub fn enum_collision_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/enum_collision.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("enum_collision.pb decode failed");
    pool.get_message_by_name("EnumCollision")
        .expect("EnumCollision not found in enum_collision.pb")
}

/// Load a `MessageDescriptor` for `SchemaSimple` from the compiled schema.
#[cfg(test)]
pub fn schema_simple_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SchemaSimple")
        .expect("SchemaSimple not found in knife.pb")
}

/// Load a `MessageDescriptor` for `SchemaOverhang` from the compiled schema.
#[cfg(test)]
pub fn schema_overhang_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SchemaOverhang")
        .expect("SchemaOverhang not found in knife.pb")
}

/// Load a `MessageDescriptor` for `SchemaInterleaved` from the compiled schema.
#[cfg(test)]
pub fn schema_interleaved_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SchemaInterleaved")
        .expect("SchemaInterleaved not found in knife.pb")
}

/// Load a `MessageDescriptor` for `SchemaHidden` from the compiled schema.
#[cfg(test)]
pub fn schema_hidden_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/knife.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("knife.pb decode failed");
    pool.get_message_by_name("SchemaHidden")
        .expect("SchemaHidden not found in knife.pb")
}

/// Load a `MessageDescriptor` for `google.protobuf.FileDescriptorProto`.
#[cfg(test)]
pub fn fdp_descriptor() -> MessageDescriptor {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.pb"));
    let pool = DescriptorPool::decode(bytes.as_ref()).expect("descriptor.pb decode failed");
    pool.get_message_by_name("google.protobuf.FileDescriptorProto")
        .expect("FileDescriptorProto not found in descriptor.pb")
}

// ── Message builder ───────────────────────────────────────────────────────────

/// A message builder accumulating wire bytes.
pub struct Message {
    buf: Vec<u8>,
    #[cfg(test)]
    pub desc: Option<MessageDescriptor>,
}

impl Message {
    pub fn new() -> Self {
        Message {
            buf: Vec::new(),
            #[cfg(test)]
            desc: None,
        }
    }

    /// Construct a schema-bound message; field names are resolved against `desc`.
    #[cfg(test)]
    pub fn with_schema(desc: MessageDescriptor) -> Self {
        Message {
            buf: Vec::new(),
            desc: Some(desc),
        }
    }

    /// Return the accumulated wire bytes.
    pub fn build(self) -> Vec<u8> {
        self.buf
    }

    /// Append raw bytes verbatim (no tag, no length prefix).
    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return a reference to the bound descriptor (test-only helper).
    #[cfg(test)]
    fn desc_ref(&self) -> Option<&MessageDescriptor> {
        self.desc.as_ref()
    }

    /// Non-test stub: always returns None.
    #[cfg(not(test))]
    #[allow(dead_code)]
    fn desc_ref(&self) -> Option<&()> {
        None
    }

    // ── Varint fields (wire type 0) ──────────────────────────────────────────

    fn add_varint_field(&mut self, tag: Tag, value: Integer) {
        self.buf
            .extend(encode_tag(tag.field, tag.wire_type, tag.ohb));
        self.buf.extend(encode_varint_ohb(value.value, value.ohb));
    }

    pub fn int32(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn int64(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn uint32(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn uint64(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn bool_(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn enum_(&mut self, field: impl IntoFieldTag, value: impl IntoInteger) {
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            value.into_integer(),
        );
    }

    pub fn sint32(&mut self, field: impl IntoFieldTag, value: i32) {
        let encoded = encode_sint32(value);
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            Integer {
                value: encoded,
                ohb: 0,
            },
        );
    }

    pub fn sint64(&mut self, field: impl IntoFieldTag, value: i64) {
        let encoded = encode_sint64(value);
        self.add_varint_field(
            field.into_field_tag(0, self.desc_ref()),
            Integer {
                value: encoded,
                ohb: 0,
            },
        );
    }

    // ── Fixed64 fields (wire type 1) ─────────────────────────────────────────

    fn add_fixed64_field(&mut self, tag: Tag, bytes: [u8; 8]) {
        self.buf
            .extend(encode_tag(tag.field, tag.wire_type, tag.ohb));
        self.buf.extend_from_slice(&bytes);
    }

    pub fn fixed64(&mut self, field: impl IntoFieldTag, value: u64) {
        self.add_fixed64_field(
            field.into_field_tag(1, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    pub fn sfixed64(&mut self, field: impl IntoFieldTag, value: i64) {
        self.add_fixed64_field(
            field.into_field_tag(1, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    pub fn double_(&mut self, field: impl IntoFieldTag, value: f64) {
        self.add_fixed64_field(
            field.into_field_tag(1, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    // ── Length-delimited fields (wire type 2) ────────────────────────────────

    fn add_len_field(&mut self, tag: Tag, payload: &[u8], len_override: Option<(usize, u8)>) {
        self.buf
            .extend(encode_tag(tag.field, tag.wire_type, tag.ohb));
        let (len, len_ohb) = len_override.unwrap_or((payload.len(), 0));
        self.buf.extend(encode_varint_ohb(len as u64, len_ohb));
        if len < payload.len() {
            self.buf.extend_from_slice(&payload[..len]);
        } else {
            self.buf.extend_from_slice(payload);
        }
    }

    pub fn bytes_(&mut self, field: impl IntoFieldTag, value: &[u8]) {
        let tag = field.into_field_tag(2, self.desc_ref());
        self.add_len_field(tag, value, None);
    }

    pub fn string(&mut self, field: impl IntoFieldTag, value: &str) {
        self.bytes_(field, value.as_bytes());
    }

    /// Append a string field with a custom length value (possibly truncated or wrong).
    pub fn string_with_len(&mut self, field: impl IntoFieldTag, len: usize, value: &str) {
        let tag = field.into_field_tag(2, self.desc_ref());
        self.add_len_field(tag, value.as_bytes(), Some((len, 0)));
    }

    /// Append a string field whose length varint has extra overhanging bytes.
    /// The length value is the actual string length; `len_ohb` is the number
    /// of overhanging varint bytes appended to the length encoding.
    pub fn string_with_len_ohb(&mut self, field: impl IntoFieldTag, len_ohb: u8, value: &str) {
        let tag = field.into_field_tag(2, self.desc_ref());
        self.add_len_field(tag, value.as_bytes(), Some((value.len(), len_ohb)));
    }

    /// Append a nested message (length-delimited).
    pub fn message(&mut self, field: impl IntoFieldTag, nested: Message) {
        let payload = nested.build();
        let tag = field.into_field_tag(2, self.desc_ref());
        self.add_len_field(tag, &payload, None);
    }

    /// Append a nested message with a custom length value (possibly wrong).
    pub fn message_with_len(
        &mut self,
        field: impl IntoFieldTag,
        len: usize,
        len_ohb: u8,
        nested: Message,
    ) {
        let payload = nested.build();
        let tag = field.into_field_tag(2, self.desc_ref());
        self.add_len_field(tag, &payload, Some((len, len_ohb)));
    }

    // ── Group fields (wire type 3 + 4) ───────────────────────────────────────

    /// Append a group (start tag + contents + end tag).
    pub fn group(&mut self, start: impl IntoFieldTag, end: impl IntoFieldTag, nested: Message) {
        let start_tag = start.into_field_tag(3, self.desc_ref());
        let end_tag = end.into_field_tag(4, self.desc_ref());
        self.buf.extend(encode_tag(
            start_tag.field,
            start_tag.wire_type,
            start_tag.ohb,
        ));
        self.buf.extend(nested.build());
        self.buf
            .extend(encode_tag(end_tag.field, end_tag.wire_type, end_tag.ohb));
    }

    // ── Fixed32 fields (wire type 5) ─────────────────────────────────────────

    fn add_fixed32_field(&mut self, tag: Tag, bytes: [u8; 4]) {
        self.buf
            .extend(encode_tag(tag.field, tag.wire_type, tag.ohb));
        self.buf.extend_from_slice(&bytes);
    }

    pub fn fixed32(&mut self, field: impl IntoFieldTag, value: u32) {
        self.add_fixed32_field(
            field.into_field_tag(5, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    pub fn sfixed32(&mut self, field: impl IntoFieldTag, value: i32) {
        self.add_fixed32_field(
            field.into_field_tag(5, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    pub fn float_(&mut self, field: impl IntoFieldTag, value: f32) {
        self.add_fixed32_field(
            field.into_field_tag(5, self.desc_ref()),
            value.to_le_bytes(),
        );
    }

    // ── Packed repeated fields ───────────────────────────────────────────────

    /// Packed varints (int32, int64, uint32, uint64, bool, enum).
    pub fn packed_varints(&mut self, field: impl IntoFieldTag, values: &[Integer]) {
        let tag = field.into_field_tag(2, self.desc_ref());
        let mut payload = Vec::new();
        for v in values {
            payload.extend(encode_varint_ohb(v.value, v.ohb));
        }
        self.add_len_field(tag, &payload, None);
    }

    /// Packed sint32 (zigzag encoded).
    pub fn packed_sint32(&mut self, field: impl IntoFieldTag, values: &[i32]) {
        let integers: Vec<Integer> = values
            .iter()
            .map(|&v| Integer {
                value: encode_sint32(v),
                ohb: 0,
            })
            .collect();
        self.packed_varints(field, &integers);
    }

    /// Packed sint64 (zigzag encoded).
    pub fn packed_sint64(&mut self, field: impl IntoFieldTag, values: &[i64]) {
        let integers: Vec<Integer> = values
            .iter()
            .map(|&v| Integer {
                value: encode_sint64(v),
                ohb: 0,
            })
            .collect();
        self.packed_varints(field, &integers);
    }

    /// Packed fixed64 / sfixed64 / double.
    pub fn packed_fixed64(&mut self, field: impl IntoFieldTag, bytes_list: Vec<[u8; 8]>) {
        let tag = field.into_field_tag(2, self.desc_ref());
        let mut payload = Vec::new();
        for b in bytes_list {
            payload.extend_from_slice(&b);
        }
        self.add_len_field(tag, &payload, None);
    }

    pub fn packed_fixed64_with_len(
        &mut self,
        field: impl IntoFieldTag,
        len: usize,
        bytes_list: Vec<[u8; 8]>,
    ) {
        let tag = field.into_field_tag(2, self.desc_ref());
        let mut payload = Vec::new();
        for b in bytes_list {
            payload.extend_from_slice(&b);
        }
        self.add_len_field(tag, &payload, Some((len, 0)));
    }

    /// Packed fixed32 / sfixed32 / float.
    pub fn packed_fixed32(&mut self, field: impl IntoFieldTag, bytes_list: Vec<[u8; 4]>) {
        let tag = field.into_field_tag(2, self.desc_ref());
        let mut payload = Vec::new();
        for b in bytes_list {
            payload.extend_from_slice(&b);
        }
        self.add_len_field(tag, &payload, None);
    }

    pub fn packed_fixed32_with_len(
        &mut self,
        field: impl IntoFieldTag,
        len: usize,
        bytes_list: Vec<[u8; 4]>,
    ) {
        let tag = field.into_field_tag(2, self.desc_ref());
        let mut payload = Vec::new();
        for b in bytes_list {
            payload.extend_from_slice(&b);
        }
        self.add_len_field(tag, &payload, Some((len, 0)));
    }
}
