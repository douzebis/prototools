// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::*;
use super::support::*;

/// Spec 0126 G2: Shift-Down/Shift-Up alias `J`/`K`'s sibling-skip
/// move, no-op-with-message on a childless-of-siblings node either
/// way.
#[test]
fn shift_down_up_alias_sibling_skip_move() {
    let mut app = message_node_app();
    app.splash = false;

    let start = app.cursor;
    app.handle_key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    let via_j = app.cursor;

    app.cursor = start;
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT));
    assert_eq!(app.cursor, via_j, "Shift-Down must match J's result");

    app.cursor = via_j;
    app.handle_key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
    let via_k = app.cursor;

    app.cursor = via_j;
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT));
    assert_eq!(app.cursor, via_k, "Shift-Up must match K's result");
}

/// Spec 0114 §1.1: the virtual encompassing wrapper protobuf makes
/// "the node under the cursor" unambiguous even at the top level, and
/// display coordinates (byte ranges, positional paths) are corrected
/// back to exactly what they were pre-wrap. Mirrors the synthetic
/// `Outer { inner: Inner { id: 5 } }` fixture in
/// `extract::tests::extract_binary_message_round_trips_through_a_fresh_decode`.
#[test]
fn wrapper_offset_and_display_range_restore_pre_wrap_coordinates() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let inner_desc = DescriptorProto {
        name: Some("Inner".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Inner".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_wrapper_offset.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc, inner_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path = std::env::temp_dir().join("protolens-tui-wrapper-offset-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Inner: field 1 varint 5 -> tag 0x08, value 0x05.
    let inner_bytes = [0x08u8, 0x05];
    // Outer wraps it as field 1 (LEN): tag (1<<3)|2 = 0x0A, len 2.
    let blob = [0x0Au8, 0x02, inner_bytes[0], inner_bytes[1]];

    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    // tag(1 byte) + length-varint(1 byte, blob.len() == 4 fits in 1 byte).
    assert_eq!(decoded.wrapper_offset, 2);
    assert_eq!(decoded.blob.len(), blob.len() + 2);

    let app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );

    // The level-0 node is the wrapper's sole field, standing in for
    // the entire original message (spec 0114 §1.1) — it did not exist
    // pre-wrap.
    let outer_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Outer"))
        .expect("tree must contain the Outer stand-in node");
    // Its whole-message payload, offset-corrected, is exactly the
    // caller's original blob.
    assert_eq!(app.display_range(outer_idx), 0..blob.len());
    // The wrapper's own node displays as bare "/".
    assert_eq!(app.positional_path(outer_idx), "/");

    let inner_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
        .expect("tree must contain the Inner submessage");
    // Byte offsets 2..4 of the *original* blob, not the wrapped one.
    assert_eq!(app.display_range(inner_idx), 2..blob.len());
    // Leading `/1` leg (descent into the wrapper's sole field) is
    // dropped — matches the path this node would have had pre-wrap.
    assert_eq!(app.positional_path(inner_idx), "/1");
}

/// `display_range` on a scalar node starts at the payload, same as a
/// message/group node: the field's own tag (and, for length-delimited
/// scalars, the length prefix) is stripped. A packed-repeated field is
/// the length-delimited case, but `IndexingTextSink::scalar_field`
/// pushes one `NodeSpan` *per element* (spec 0115), each already
/// bare-payload (`packed_record_start: Some(...)`) — so `display_range`
/// on one of those element nodes returns that element's own byte
/// unstripped, not the whole record's tag+length-stripped payload.
#[test]
fn display_range_strips_tag_and_length_for_scalars_including_packed() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let msg_desc = DescriptorProto {
        name: Some("Msg".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("vals".to_string()),
                number: Some(2),
                label: Some(Label::Repeated as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_display_range_scalars.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![msg_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path =
        std::env::temp_dir().join("protolens-tui-display-range-scalars-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // id: field 1 varint 5 -> tag 0x08, value 0x05.
    // vals: field 2 (LEN, packed) tag (2<<3)|2 = 0x12, len 3, payload
    // [0x01, 0x02, 0x03] (three varint elements 1, 2, 3).
    let blob = [0x08u8, 0x05, 0x12, 0x03, 0x01, 0x02, 0x03];

    let decoded = decode(&blob, &mut ctx, Some("test.Msg"), 2).unwrap();
    let app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );

    let id_idx = app
        .tree
        .iter()
        .position(|n| n.span.field_number == 1)
        .expect("tree must contain the id field");
    assert!(!app.tree[id_idx].span.is_message);
    // Tag (1 byte) stripped: just the varint value byte.
    assert_eq!(app.display_range(id_idx), 1..2);

    let vals_indices: Vec<usize> = app
        .tree
        .iter()
        .enumerate()
        .filter(|(_, n)| n.span.field_number == 2)
        .map(|(i, _)| i)
        .collect();
    // One NodeSpan per packed element (spec 0115), not one for the
    // whole record.
    assert_eq!(vals_indices.len(), 3);
    for idx in &vals_indices {
        assert!(!app.tree[*idx].span.is_message);
        assert!(app.tree[*idx].span.packed_record_start.is_some());
    }
    // Each element's own byte, already bare-payload — no further
    // tag/length stripping applied.
    assert_eq!(app.display_range(vals_indices[0]), 4..5);
    assert_eq!(app.display_range(vals_indices[1]), 5..6);
    assert_eq!(app.display_range(vals_indices[2]), 6..7);
}

/// Regression test: the always-reserved heat-cue gutter column (spec
/// 0138 N1) leaves only `main_area.width - 1` columns for line text, so
/// `pan_right`'s clamp must account for it or panning stops one
/// character short of the line's true end.
#[test]
fn pan_right_reaches_the_true_end_of_the_longest_visible_line() {
    let line = "x".repeat(50);
    let mut app = sibling_leaves_app(&[&line]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 10, 5);

    for _ in 0..20 {
        app.pan_right();
    }

    let usable_width = app.main_area.width as usize - 1;
    assert_eq!(
        app.pan_offset,
        line.len() - usable_width,
        "pan_offset must clamp so the last column of the pane shows the \
         line's last character, leaving room for the 1-column heat-cue \
         gutter"
    );
}
