// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message as ProstMessage;
use prost_types::{field_descriptor_proto::Type, FileDescriptorProto, FileDescriptorSet};

// ── Enum value collection ──────────────────────────────────────────────────────

/// Temporary map from fully-qualified enum type name → sorted `(i32, name)` table.
type EnumValueMap = HashMap<String, Vec<(i32, Box<str>)>>;

// ── Public types ──────────────────────────────────────────────────────────────

/// Per-field information extracted from a FieldDescriptorProto.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name (for annotations).
    pub name: String,
    /// Proto type constant (matches Python's FieldDescriptor.TYPE_* values).
    pub proto_type: i32,
    /// Label constant (LABEL_OPTIONAL = 1, LABEL_REQUIRED = 2, LABEL_REPEATED = 3).
    pub label: i32,
    /// `true` for repeated scalar fields encoded as packed (proto2 [packed=true]
    /// or proto3 implicit packing).
    pub is_packed: bool,
    /// Fully-qualified type name for MESSAGE / GROUP fields (e.g. ".pkg.Inner").
    pub nested_type_name: Option<String>,
    /// Enum type name for ENUM fields (for annotations).
    pub enum_type_name: Option<String>,
    /// Enum/message name (short) for annotations.
    pub type_display_name: Option<String>,
    /// Numeric value → symbolic name table for ENUM fields.
    /// Sorted by numeric value for O(log n) lookup via binary_search_by_key.
    /// Empty for non-ENUM fields.
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

/// The parsed, indexed form of a FileDescriptorProto/Set.
///
/// `root_type_name` is the fully-qualified name of the root message (the one
/// that corresponds to a `foo.pb` payload).  `messages` maps every reachable
/// type to its `MessageSchema`.
pub struct ParsedSchema {
    pub root_type_name: String,
    pub messages: HashMap<String, Arc<MessageSchema>>,
    /// OPT-6: Pre-built Arc<HashMap> for the protoc renderer so `get_schemas()`
    /// in lib.rs does not rebuild it on every `encode_pb("protoc")` call.
    /// Built once at `parse_schema()` time and shared across all calls.
    pub all_schemas: Arc<HashMap<String, Arc<MessageSchema>>>,
}

impl ParsedSchema {
    /// Construct an empty (no-schema) `ParsedSchema`.
    ///
    /// Equivalent to `parse_schema(b"", "")` but infallible and allocation-free.
    pub fn empty() -> Self {
        ParsedSchema {
            root_type_name: String::new(),
            messages: HashMap::new(),
            all_schemas: Arc::new(HashMap::new()),
        }
    }

    /// Return the `MessageSchema` for the root message, or `None` for an empty
    /// schema (no-schema mode, equivalent to `ctx.schema = None`).
    pub fn root_schema(&self) -> Option<Arc<MessageSchema>> {
        if self.root_type_name.is_empty() {
            None
        } else {
            self.messages.get(&self.root_type_name).cloned()
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a protobuf schema descriptor.
#[non_exhaustive]
#[derive(Debug)]
pub enum SchemaError {
    /// `schema_bytes` could not be decoded as a `FileDescriptorSet` or
    /// `FileDescriptorProto`.
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
/// Tries `FileDescriptorSet` first, falls back to `FileDescriptorProto`,
/// mirroring the Python `load_schema_descriptor` behaviour.
///
/// An empty `schema_bytes` or empty `root_msg_name` returns a schema whose
/// `root_schema()` is `None` (no-schema mode).
pub fn parse_schema(schema_bytes: &[u8], root_msg_name: &str) -> Result<ParsedSchema, SchemaError> {
    if schema_bytes.is_empty() || root_msg_name.is_empty() {
        return Ok(ParsedSchema {
            root_type_name: String::new(),
            messages: HashMap::new(),
            all_schemas: Arc::new(HashMap::new()), // OPT-6: empty cache
        });
    }

    // Collect all FileDescriptorProtos: try FDS first, then bare FDP.
    let files: Vec<FileDescriptorProto> = if let Ok(fds) = FileDescriptorSet::decode(schema_bytes) {
        fds.file
    } else if let Ok(fdp) = FileDescriptorProto::decode(schema_bytes) {
        vec![fdp]
    } else {
        return Err(SchemaError::InvalidDescriptor(
            "schema_bytes is neither a valid FileDescriptorSet nor FileDescriptorProto".into(),
        ));
    };

    // Build a global registry of type_name → DescriptorProto (flat, all files).
    // Keys are fully-qualified names like ".package.MessageName".
    let mut raw: HashMap<String, prost_types::DescriptorProto> = HashMap::new();
    for file in &files {
        let pkg = file.package.as_deref().unwrap_or("");
        collect_message_types(pkg, &file.message_type, &mut raw);
    }

    // Pass 1: collect all enum value tables from all files.
    // Keys are fully-qualified enum type names like ".google.protobuf.FieldDescriptorProto.Type".
    let mut enum_map: EnumValueMap = HashMap::new();
    for file in &files {
        let pkg = file.package.as_deref().unwrap_or("");
        collect_enum_types(pkg, &file.enum_type, &mut enum_map);
        // Also collect enums nested inside message types.
        collect_nested_enum_types(pkg, &file.message_type, &mut enum_map);
    }

    // Now build MessageSchema for every collected type.
    let mut messages: HashMap<String, Arc<MessageSchema>> = HashMap::new();
    for (fqn, dp) in &raw {
        let schema = build_message_schema(dp, &raw, &enum_map);
        messages.insert(fqn.clone(), Arc::new(schema));
    }

    // Normalise root_msg_name: add leading dot if missing.
    let root_type_name = if root_msg_name.starts_with('.') {
        root_msg_name.to_string()
    } else {
        format!(".{}", root_msg_name)
    };

    if !messages.contains_key(&root_type_name) {
        return Err(SchemaError::MessageNotFound(format!(
            "root message '{}' not found in schema (available: {})",
            root_type_name,
            messages.keys().cloned().collect::<Vec<_>>().join(", ")
        )));
    }

    // OPT-6: build all_schemas once here so get_schemas() in lib.rs can just
    // clone the Arc instead of rebuilding the HashMap on every encode_pb("protoc").
    let all_schemas = Arc::new(
        messages
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect::<HashMap<_, _>>(),
    );

    Ok(ParsedSchema {
        root_type_name,
        messages,
        all_schemas,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Recursively collect all DescriptorProtos from a list of top-level or nested
/// message types, building their fully-qualified names.
fn collect_message_types(
    parent_prefix: &str,
    descriptors: &[prost_types::DescriptorProto],
    out: &mut HashMap<String, prost_types::DescriptorProto>,
) {
    for dp in descriptors {
        let name = dp.name.as_deref().unwrap_or("");
        let fqn = if parent_prefix.is_empty() {
            format!(".{}", name)
        } else {
            format!(".{}.{}", parent_prefix, name)
        };
        // Recurse into nested types before inserting (order doesn't matter for HashMap).
        let nested_prefix = if parent_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", parent_prefix, name)
        };
        collect_message_types(&nested_prefix, &dp.nested_type, out);
        out.insert(fqn, dp.clone());
    }
}

/// Build a `MessageSchema` from a `DescriptorProto`.
fn build_message_schema(
    dp: &prost_types::DescriptorProto,
    _all: &HashMap<String, prost_types::DescriptorProto>,
    enum_map: &EnumValueMap,
) -> MessageSchema {
    let mut fields = HashMap::new();
    for fdp in &dp.field {
        let number = match fdp.number {
            Some(n) => n as u32,
            None => continue,
        };
        let proto_type = fdp.r#type.unwrap_or(0);
        let label = fdp.label.unwrap_or(0);

        // Determine if the field is packed.
        // The options.packed flag is set by protoc for both proto2 [packed=true]
        // and proto3 implicit packed fields.
        let is_packed = fdp.options.as_ref().and_then(|o| o.packed).unwrap_or(false);

        // For proto3, repeated scalar fields are packed by default even if
        // options.packed is not set in the descriptor.  Check syntax.
        // (We use a simple heuristic: if label==REPEATED and type is scalar,
        //  treat it as packed for proto3 files.  We don't have the file syntax
        //  here, so we rely on protoc having already set options.packed.)
        // In practice, protoc sets options.packed=true for all packed fields.

        let nested_type_name = fdp.type_name.clone();

        // Short display name for annotations (last component of type_name).
        let type_display_name = nested_type_name
            .as_ref()
            .map(|tn| tn.rsplit('.').next().unwrap_or(tn).to_string());

        // Enum type name (only for ENUM fields).
        let enum_type_name = if proto_type == Type::Enum as i32 {
            nested_type_name.clone()
        } else {
            None
        };

        // Resolve enum value table for ENUM fields (pass 2 — enum_map already built).
        let enum_values: Box<[(i32, Box<str>)]> = if proto_type == Type::Enum as i32 {
            if let Some(etn) = &enum_type_name {
                if let Some(vals) = enum_map.get(etn.as_str()) {
                    vals.iter()
                        .map(|(n, s)| (*n, s.clone()))
                        .collect::<Vec<_>>()
                        .into_boxed_slice()
                } else {
                    Box::default()
                }
            } else {
                Box::default()
            }
        } else {
            Box::default()
        };

        let fi = FieldInfo {
            name: fdp.name.clone().unwrap_or_default(),
            proto_type,
            label,
            is_packed,
            nested_type_name: if proto_type == Type::Message as i32
                || proto_type == Type::Group as i32
            {
                nested_type_name
            } else {
                None
            },
            enum_type_name,
            type_display_name,
            enum_values,
        };
        fields.insert(number, fi);
    }

    MessageSchema {
        name: dp.name.clone().unwrap_or_default(),
        fields,
    }
}

/// Collect top-level enum types from a file into the enum_map.
fn collect_enum_types(
    parent_prefix: &str,
    enums: &[prost_types::EnumDescriptorProto],
    out: &mut EnumValueMap,
) {
    for edp in enums {
        let name = edp.name.as_deref().unwrap_or("");
        let fqn = if parent_prefix.is_empty() {
            format!(".{}", name)
        } else {
            format!(".{}.{}", parent_prefix, name)
        };
        let mut vals: Vec<(i32, Box<str>)> = edp
            .value
            .iter()
            .filter_map(|vdp| {
                let n = vdp.number?;
                let s: Box<str> = vdp.name.as_deref().unwrap_or("").into();
                Some((n, s))
            })
            .collect();
        vals.sort_by_key(|(n, _)| *n);
        out.insert(fqn, vals);
    }
}

/// Recursively collect enum types nested inside message types.
fn collect_nested_enum_types(
    parent_prefix: &str,
    descriptors: &[prost_types::DescriptorProto],
    out: &mut EnumValueMap,
) {
    for dp in descriptors {
        let name = dp.name.as_deref().unwrap_or("");
        let prefix = if parent_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", parent_prefix, name)
        };
        collect_enum_types(&prefix, &dp.enum_type, out);
        collect_nested_enum_types(&prefix, &dp.nested_type, out);
    }
}

// ── Proto type constants (matching Python's FieldDescriptor.TYPE_*) ────────────

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
