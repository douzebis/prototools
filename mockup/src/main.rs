// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

// Mockup: validate the fixture!/msg_fields! macro design for protocraft spec 0013.
//
// Syntax:
//   fixture!(name, SCHEMA; fields...) -> pub fn name() -> Vec<u8>
//   scalar:  uint64("field", value),  uint64(NUM, value),  fixed64(...),  bytes_(...),  uint32(...)
//   nested:  message("field"; fields...),  group("field"; fields...),  group(NUM; fields...)

// ── Mock descriptor ───────────────────────────────────────────────────────────

struct Descriptor {
    name: &'static str,
    fields: &'static [(&'static str, u64, u8, Option<&'static Descriptor>)],
    // (name, field_number, wire_type, nested_descriptor)
}

impl Descriptor {
    fn resolve(&self, name: &str) -> (u64, u8, Option<&'static Descriptor>) {
        for &(n, number, wt, desc) in self.fields {
            if n == name {
                return (number, wt, desc);
            }
        }
        panic!("field '{}' not found in descriptor '{}'", name, self.name);
    }
}

// Descriptor for the nested SwissArmyKnife message (field 113 inside GROUP).
static NESTED_DESC: Descriptor = Descriptor {
    name: "Nested",
    fields: &[
        ("fixed64Rp", 46, 1, None),
        ("bytesRp", 52, 2, None),
        ("uint32Rp", 53, 0, None),
    ],
};

// Descriptor for the GROUP group type (field 13 of SwissArmyKnife).
// Its only field is "nested" (113), which is a message of type Nested.
static GROUP_DESC: Descriptor = Descriptor {
    name: "GROUP",
    fields: &[("nested", 113, 2, Some(&NESTED_DESC))],
};

static KNIFE: Descriptor = Descriptor {
    name: "SwissArmyKnife",
    fields: &[
        ("uint64Rp", 44, 0, None),
        ("fixed64Rp", 46, 1, None),
        ("bytesRp", 52, 2, None),
        ("uint32Rp", 53, 0, None),
        ("group", 13, 3, Some(&GROUP_DESC)),
        ("nested", 113, 2, Some(&NESTED_DESC)),
    ],
};

// ── FieldSpec trait ───────────────────────────────────────────────────────────
//
// Resolves a field specifier to (field_number, nested_descriptor).
// &str  → descriptor lookup (panics if no descriptor or name not found)
// u64/u32/usize → pass-through, no descriptor needed

trait FieldSpec {
    fn resolve(self, desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>);
}

impl FieldSpec for &str {
    fn resolve(self, desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        let d = desc.unwrap_or_else(|| panic!("no descriptor bound, cannot resolve '{}'", self));
        let (num, _wt, nested) = d.resolve(self);
        (num, nested)
    }
}

impl FieldSpec for u64 {
    fn resolve(self, _desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        (self, None)
    }
}

impl FieldSpec for u32 {
    fn resolve(self, _desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        (self as u64, None)
    }
}

impl FieldSpec for usize {
    fn resolve(self, _desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        (self as u64, None)
    }
}

impl FieldSpec for i32 {
    fn resolve(self, _desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        (self as u64, None)
    }
}

impl FieldSpec for i64 {
    fn resolve(self, _desc: Option<&'static Descriptor>) -> (u64, Option<&'static Descriptor>) {
        (self as u64, None)
    }
}

// ── Message builder ───────────────────────────────────────────────────────────

struct Message {
    buf: Vec<u8>,
    desc: Option<&'static Descriptor>,
}

impl Message {
    fn new() -> Self {
        Message {
            buf: Vec::new(),
            desc: None,
        }
    }
    fn with_schema(desc: &'static Descriptor) -> Self {
        Message {
            buf: Vec::new(),
            desc: Some(desc),
        }
    }
    fn encode_varint(buf: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                buf.push(b);
                break;
            } else {
                buf.push(b | 0x80);
            }
        }
    }
    fn push_tag(&mut self, field: u64, wire_type: u8) {
        Self::encode_varint(&mut self.buf, (field << 3) | wire_type as u64);
    }
    fn varint_field(&mut self, field: u64, value: u64) {
        self.push_tag(field, 0);
        Self::encode_varint(&mut self.buf, value);
    }
    fn fixed64_field(&mut self, field: u64, value: u64) {
        self.push_tag(field, 1);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }
    fn bytes_field(&mut self, field: u64, value: &[u8]) {
        self.push_tag(field, 2);
        Self::encode_varint(&mut self.buf, value.len() as u64);
        self.buf.extend_from_slice(value);
    }
    fn message_field(&mut self, field: u64, nested: Message) {
        let payload = nested.buf;
        self.push_tag(field, 2);
        Self::encode_varint(&mut self.buf, payload.len() as u64);
        self.buf.extend_from_slice(&payload);
    }
    fn group_field(&mut self, start_field: u64, end_field: u64, nested: Message) {
        self.push_tag(start_field, 3);
        self.buf.extend_from_slice(&nested.buf);
        self.push_tag(end_field, 4);
    }
    fn build(self) -> Vec<u8> {
        self.buf
    }
}

// ── Macros ────────────────────────────────────────────────────────────────────

macro_rules! msg_fields {
    ($m:ident,) => {};

    // group(field; nested...) — field is &str (name lookup) or integer (raw number)
    // Group body uses the group field's own message_type descriptor.
    ($m:ident, group($field:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let (_num, _gdesc) = FieldSpec::resolve($field, $m.desc);
        let mut _nm = if let Some(d) = _gdesc { Message::with_schema(d) } else { Message::new() };
        msg_fields!(_nm, $($nested)*);
        $m.group_field(_num, _num, _nm);
        msg_fields!($m, $($rest)*);
    }};

    // message(field; nested...) — field is &str or integer
    // Nested message gets the field's own descriptor (message_type).
    ($m:ident, message($field:expr; $($nested:tt)*), $($rest:tt)*) => {{
        let (_num, _desc) = FieldSpec::resolve($field, $m.desc);
        let mut _nm = if let Some(d) = _desc { Message::with_schema(d) } else { Message::new() };
        msg_fields!(_nm, $($nested)*);
        $m.message_field(_num, _nm);
        msg_fields!($m, $($rest)*);
    }};

    // uint64(field, value)
    ($m:ident, uint64($field:expr, $val:expr), $($rest:tt)*) => {{
        let (_num, _) = FieldSpec::resolve($field, $m.desc);
        $m.varint_field(_num, $val as u64);
        msg_fields!($m, $($rest)*);
    }};

    // fixed64(field, value)
    ($m:ident, fixed64($field:expr, $val:expr), $($rest:tt)*) => {{
        let (_num, _) = FieldSpec::resolve($field, $m.desc);
        $m.fixed64_field(_num, $val as u64);
        msg_fields!($m, $($rest)*);
    }};

    // bytes_(field, value)
    ($m:ident, bytes_($field:expr, $val:expr), $($rest:tt)*) => {{
        let (_num, _) = FieldSpec::resolve($field, $m.desc);
        $m.bytes_field(_num, $val);
        msg_fields!($m, $($rest)*);
    }};

    // uint32(field, value)
    ($m:ident, uint32($field:expr, $val:expr), $($rest:tt)*) => {{
        let (_num, _) = FieldSpec::resolve($field, $m.desc);
        $m.varint_field(_num, $val as u64);
        msg_fields!($m, $($rest)*);
    }};
}

macro_rules! fixture {
    ($name:ident, $schema:expr; $($fields:tt)*) => {
        pub fn $name() -> Vec<u8> {
            let mut _m = Message::with_schema($schema);
            msg_fields!(_m, $($fields)*);
            _m.build()
        }
    };
}

// ── Fixture ───────────────────────────────────────────────────────────────────

fixture!(test_proto2_level, &KNIFE;
    uint64("uint64Rp", 0),
    fixed64("fixed64Rp", 0),
    bytes_("bytesRp", b""),
    group(4;
        uint64(11, 0),
    ),
    group("group";
        message("nested";
            fixed64("fixed64Rp", 0),
            bytes_("bytesRp", b""),
            uint32("uint32Rp", 0),
        ),
    ),
    uint32("uint32Rp", 0),
);

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let bytes = test_proto2_level();
    print!("got      ({} bytes):", bytes.len());
    for b in &bytes {
        print!(" {:02x}", b);
    }
    println!();

    // Expected from committed fixture:
    // field 44 varint 0, field 46 fixed64 0, field 52 len 0
    // group 4 { field 11 varint 0 } end 4
    // group 13 { field 113 len { field 46 fixed64 0, field 52 len 0, field 53 varint 0 } } end 13
    // field 53 varint 0
    let expected: &[u8] = &[
        0xe0, 0x02, 0x00, 0xf1, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2, 0x03, 0x00, 0x23, 0x58, 0x00,
        0x24, 0x6b, 0x8a, 0x07, 0x10, 0xf1, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2, 0x03, 0x00, 0xa8,
        0x03, 0x00, 0x6c, 0xa8, 0x03, 0x00,
    ];
    print!("expected ({} bytes):", expected.len());
    for b in expected {
        print!(" {:02x}", b);
    }
    println!();
    println!("match: {}", bytes == expected);
}
