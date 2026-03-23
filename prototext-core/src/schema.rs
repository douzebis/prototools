// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;

use prost_reflect::{Cardinality, DescriptorPool, FieldDescriptor, Kind, MessageDescriptor};

// ── Compatibility shim types ───────────────────────────────────────────────────
//
// FieldInfo and MessageSchema are kept during the transition so that
// decoder.rs / render_text / etc. continue to compile unchanged.
// They are populated from prost-reflect descriptors and will be removed
// once all callers are migrated to use FieldDescriptor directly.

/// Per-field information extracted from a FieldDescriptor.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name (for annotations).
    pub name: String,
    /// Proto type constant (matches Python's FieldDescriptor.TYPE_* values).
    pub proto_type: i32,
    /// Label constant (LABEL_OPTIONAL = 1, LABEL_REQUIRED = 2, LABEL_REPEATED = 3).
    pub label: i32,
    /// `true` for repeated scalar fields encoded as packed.
    pub is_packed: bool,
    /// Fully-qualified type name for MESSAGE / GROUP fields (with leading dot).
    pub nested_type_name: Option<String>,
    /// Enum type name for ENUM fields (for annotations).
    pub enum_type_name: Option<String>,
    /// Enum/message name (short) for annotations.
    pub type_display_name: Option<String>,
    /// Numeric value → symbolic name table for ENUM fields.
    /// Sorted by numeric value for O(log n) lookup via binary_search_by_key.
    pub enum_values: Box<[(i32, Box<str>)]>,
}

/// Schema for one protobuf message type: maps field number → FieldInfo.
#[derive(Debug)]
pub struct MessageSchema {
    /// Short message name (for annotations).
    pub name: String,
    /// Field-number to FieldInfo map.
    pub fields: HashMap<u32, FieldInfo>,
}

// ── Public types ──────────────────────────────────────────────────────────────

/// The parsed, indexed form of a `FileDescriptorSet`.
///
/// Owns a `DescriptorPool` and a cached root message name.
/// The compatibility shim also pre-builds the `MessageSchema` maps used
/// by the current renderer; these will be removed after full migration.
pub struct ParsedSchema {
    pool: DescriptorPool,
    root_full_name: String,

    // ── Compatibility shim (to be removed after migration) ───────────────────
    pub messages: HashMap<String, Arc<MessageSchema>>,
    pub all_schemas: Arc<HashMap<String, Arc<MessageSchema>>>,
}

impl ParsedSchema {
    /// Construct an empty (no-schema) `ParsedSchema`.
    pub fn empty() -> Self {
        ParsedSchema {
            pool: DescriptorPool::new(),
            root_full_name: String::new(),
            messages: HashMap::new(),
            all_schemas: Arc::new(HashMap::new()),
        }
    }

    /// Return the `MessageSchema` for the root message, or `None` for an empty
    /// schema (no-schema mode).
    ///
    /// Returns an `Arc<MessageSchema>` from the shim cache for backward
    /// compatibility with the current renderer.
    pub fn root_schema(&self) -> Option<Arc<MessageSchema>> {
        if self.root_full_name.is_empty() {
            None
        } else {
            // shim: look up by prost-reflect FQN (no leading dot)
            self.messages.get(&self.root_full_name).cloned()
        }
    }

    /// Return the `MessageDescriptor` for the root message, or `None`.
    pub fn root_descriptor(&self) -> Option<MessageDescriptor> {
        if self.root_full_name.is_empty() {
            None
        } else {
            self.pool.get_message_by_name(&self.root_full_name)
        }
    }

    /// Look up a message by fully-qualified name.
    pub fn get_descriptor(&self, fqn: &str) -> Option<MessageDescriptor> {
        self.pool.get_message_by_name(fqn)
    }

    /// Access the underlying pool.
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a protobuf schema descriptor.
#[non_exhaustive]
#[derive(Debug)]
pub enum SchemaError {
    /// `schema_bytes` could not be decoded as a `FileDescriptorSet`.
    InvalidDescriptor(String),
    /// The requested root message was not found in the parsed descriptor.
    MessageNotFound(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::InvalidDescriptor(msg) => write!(f, "invalid descriptor: {msg}"),
            SchemaError::MessageNotFound(msg) => write!(f, "message not found: {msg}"),
        }
    }
}

impl std::error::Error for SchemaError {}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse `schema_bytes` into a `ParsedSchema`.
///
/// An empty `schema_bytes` or empty `root_msg_name` returns a schema whose
/// `root_schema()` is `None` (no-schema mode).
pub fn parse_schema(schema_bytes: &[u8], root_msg_name: &str) -> Result<ParsedSchema, SchemaError> {
    if schema_bytes.is_empty() || root_msg_name.is_empty() {
        return Ok(ParsedSchema::empty());
    }

    let pool = DescriptorPool::decode(schema_bytes)
        .map_err(|e| SchemaError::InvalidDescriptor(e.to_string()))?;

    // prost-reflect uses no leading dot; strip one if the caller passed it.
    let root_full_name = root_msg_name.trim_start_matches('.').to_string();

    if pool.get_message_by_name(&root_full_name).is_none() {
        let available = pool
            .all_messages()
            .map(|m| m.full_name().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(SchemaError::MessageNotFound(format!(
            "root message '{}' not found in schema (available: {})",
            root_full_name, available
        )));
    }

    // Build the compatibility shim: populate MessageSchema / FieldInfo for every
    // message in the pool, keyed by prost-reflect FQN (no leading dot).
    let messages = build_shim(&pool);
    let all_schemas = Arc::new(
        messages
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect::<HashMap<_, _>>(),
    );

    Ok(ParsedSchema {
        pool,
        root_full_name,
        messages,
        all_schemas,
    })
}

// ── Compatibility shim builder ────────────────────────────────────────────────

/// Build a `HashMap<FQN, Arc<MessageSchema>>` from all messages in the pool.
///
/// Keys use prost-reflect FQNs (no leading dot).  The rest of the codebase
/// still uses leading-dot FQNs for nested_type_name lookups; those are
/// stored with the leading dot in `FieldInfo::nested_type_name` and looked
/// up via the shim translation layer in `ParsedSchema::messages` (which
/// stores both FQN variants — see lookup_nested_schema).
fn build_shim(pool: &DescriptorPool) -> HashMap<String, Arc<MessageSchema>> {
    let mut out: HashMap<String, Arc<MessageSchema>> = HashMap::new();
    for msg in pool.all_messages() {
        let schema = message_schema_from_descriptor(&msg);
        // Store under prost-reflect FQN (no leading dot).
        out.insert(msg.full_name().to_string(), Arc::new(schema));
        // Also store under leading-dot FQN for backward-compat lookups.
        out.insert(
            format!(".{}", msg.full_name()),
            out[msg.full_name()].clone(),
        );
    }
    out
}

/// Build a `MessageSchema` from a `MessageDescriptor`.
fn message_schema_from_descriptor(msg: &MessageDescriptor) -> MessageSchema {
    let mut fields: HashMap<u32, FieldInfo> = HashMap::new();

    for field in msg.fields() {
        let fi = field_info_from_descriptor(&field);
        fields.insert(field.number(), fi);
    }

    MessageSchema {
        name: msg.name().to_string(),
        fields,
    }
}

/// Build a `FieldInfo` from a `FieldDescriptor`.
fn field_info_from_descriptor(field: &FieldDescriptor) -> FieldInfo {
    let proto_type = kind_to_proto_type_for_field(field);
    let label = cardinality_to_label(field.cardinality());
    let is_packed = field.is_packed();

    let (nested_type_name, enum_type_name, type_display_name, enum_values) = match field.kind() {
        Kind::Message(msg_desc) => {
            // Groups are represented as Kind::Message in prost-reflect; detect via is_group().
            let fqn = format!(".{}", msg_desc.full_name());
            let display = msg_desc.name().to_string();
            (Some(fqn), None, Some(display), Box::default())
        }
        Kind::Enum(enum_desc) => {
            let fqn = format!(".{}", enum_desc.full_name());
            let display = enum_desc.name().to_string();
            let mut vals: Vec<(i32, Box<str>)> = enum_desc
                .values()
                .map(|v| (v.number(), v.name().into()))
                .collect();
            vals.sort_by_key(|(n, _)| *n);
            vals.dedup_by_key(|(n, _)| *n); // keep first name for duplicate numbers
            (None, Some(fqn), Some(display), vals.into_boxed_slice())
        }
        _ => (None, None, None, Box::default()),
    };

    FieldInfo {
        name: field.name().to_string(),
        proto_type,
        label,
        is_packed,
        nested_type_name,
        enum_type_name,
        type_display_name,
        enum_values,
    }
}

// ── Proto type / label integer constants (compatibility) ─────────────────────

/// Map a prost-reflect `Kind` to the legacy `proto_type` integer constant.
/// Map a prost-reflect `Kind` to the legacy `proto_type` integer constant.
///
/// Groups appear as `Kind::Message`; the caller must check `field.is_group()`
/// separately to distinguish GROUP from MESSAGE.
fn kind_to_proto_type_for_field(field: &FieldDescriptor) -> i32 {
    match field.kind() {
        Kind::Double => proto_type::DOUBLE,
        Kind::Float => proto_type::FLOAT,
        Kind::Int64 => proto_type::INT64,
        Kind::Uint64 => proto_type::UINT64,
        Kind::Int32 => proto_type::INT32,
        Kind::Fixed64 => proto_type::FIXED64,
        Kind::Fixed32 => proto_type::FIXED32,
        Kind::Bool => proto_type::BOOL,
        Kind::String => proto_type::STRING,
        Kind::Message(_) => {
            if field.is_group() {
                proto_type::GROUP
            } else {
                proto_type::MESSAGE
            }
        }
        Kind::Bytes => proto_type::BYTES,
        Kind::Uint32 => proto_type::UINT32,
        Kind::Enum(_) => proto_type::ENUM,
        Kind::Sfixed32 => proto_type::SFIXED32,
        Kind::Sfixed64 => proto_type::SFIXED64,
        Kind::Sint32 => proto_type::SINT32,
        Kind::Sint64 => proto_type::SINT64,
    }
}

/// Map a prost-reflect `Cardinality` to the legacy `proto_label` integer constant.
fn cardinality_to_label(cardinality: Cardinality) -> i32 {
    match cardinality {
        Cardinality::Optional => proto_label::OPTIONAL,
        Cardinality::Required => proto_label::REQUIRED,
        Cardinality::Repeated => proto_label::REPEATED,
    }
}

pub mod proto_type {
    pub const DOUBLE: i32 = 1;
    pub const FLOAT: i32 = 2;
    pub const INT64: i32 = 3;
    pub const UINT64: i32 = 4;
    pub const INT32: i32 = 5;
    pub const FIXED64: i32 = 6;
    pub const FIXED32: i32 = 7;
    pub const BOOL: i32 = 8;
    pub const STRING: i32 = 9;
    pub const GROUP: i32 = 10;
    pub const MESSAGE: i32 = 11;
    pub const BYTES: i32 = 12;
    pub const UINT32: i32 = 13;
    pub const ENUM: i32 = 14;
    pub const SFIXED32: i32 = 15;
    pub const SFIXED64: i32 = 16;
    pub const SINT32: i32 = 17;
    pub const SINT64: i32 = 18;
}

pub mod proto_label {
    pub const OPTIONAL: i32 = 1;
    pub const REQUIRED: i32 = 2;
    pub const REPEATED: i32 = 3;
}

// ── Unit tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
    use prost_types::{
        DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
        FileDescriptorProto, FileDescriptorSet,
    };

    /// Build a minimal FileDescriptorSet bytes containing one file with the
    /// given message descriptor and any top-level enums provided.
    fn build_fds(enums: Vec<EnumDescriptorProto>, message: DescriptorProto) -> Vec<u8> {
        let file = FileDescriptorProto {
            name: Some("test.proto".into()),
            syntax: Some("proto2".into()),
            enum_type: enums,
            message_type: vec![message],
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };
        let mut buf = Vec::new();
        fds.encode(&mut buf).unwrap();
        buf
    }

    fn enum_value(name: &str, number: i32) -> EnumValueDescriptorProto {
        EnumValueDescriptorProto {
            name: Some(name.into()),
            number: Some(number),
            ..Default::default()
        }
    }

    fn enum_field(name: &str, number: i32, type_name: &str) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.into()),
            number: Some(number),
            r#type: Some(proto_type::ENUM),
            label: Some(proto_label::OPTIONAL),
            type_name: Some(type_name.into()),
            ..Default::default()
        }
    }

    fn int32_field(name: &str, number: i32) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.into()),
            number: Some(number),
            r#type: Some(proto_type::INT32),
            label: Some(proto_label::OPTIONAL),
            ..Default::default()
        }
    }

    // ── §8.1 Two-pass enum collection ─────────────────────────────────────────

    #[test]
    fn two_pass_enum_collection() {
        // Schema: enum Color { RED=0; GREEN=1; BLUE=2; }
        //         message Msg { optional Color color = 1; optional int32 id = 2; }
        let color_enum = EnumDescriptorProto {
            name: Some("Color".into()),
            value: vec![
                enum_value("RED", 0),
                enum_value("GREEN", 1),
                enum_value("BLUE", 2),
            ],
            ..Default::default()
        };
        let msg = DescriptorProto {
            name: Some("Msg".into()),
            field: vec![enum_field("color", 1, ".Color"), int32_field("id", 2)],
            ..Default::default()
        };
        let fds_bytes = build_fds(vec![color_enum], msg);
        let schema = parse_schema(&fds_bytes, "Msg").unwrap();
        let root = schema.root_schema().unwrap();

        let color_fi = root.fields.get(&1).expect("field 1 must exist");
        assert_eq!(
            color_fi.enum_values.as_ref(),
            &[(0, "RED".into()), (1, "GREEN".into()), (2, "BLUE".into())],
            "enum_values must be sorted by numeric value"
        );

        let id_fi = root.fields.get(&2).expect("field 2 must exist");
        assert!(
            id_fi.enum_values.is_empty(),
            "non-enum field must have empty enum_values"
        );
    }

    // ── §8.2 Enum named after primitive keyword ────────────────────────────────

    #[test]
    fn enum_named_float_not_mistaken_for_primitive() {
        // Schema: enum float { FLOAT_ZERO=0; FLOAT_ONE=1; }
        //         message Msg { optional float kind = 1; }
        let float_enum = EnumDescriptorProto {
            name: Some("float".into()),
            value: vec![enum_value("FLOAT_ZERO", 0), enum_value("FLOAT_ONE", 1)],
            ..Default::default()
        };
        let msg = DescriptorProto {
            name: Some("Msg".into()),
            field: vec![enum_field("kind", 1, ".float")],
            ..Default::default()
        };
        let fds_bytes = build_fds(vec![float_enum], msg);
        let schema = parse_schema(&fds_bytes, "Msg").unwrap();
        let root = schema.root_schema().unwrap();

        let kind_fi = root.fields.get(&1).expect("field 1 must exist");
        assert_eq!(
            kind_fi.proto_type,
            proto_type::ENUM,
            "field named 'float' backed by an enum must have proto_type=ENUM"
        );
        assert!(
            !kind_fi.enum_values.is_empty(),
            "enum named 'float' must have non-empty enum_values"
        );
    }
}
