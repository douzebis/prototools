;;; SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
;;;
;;; SPDX-License-Identifier: MIT

; Base captures (unchanged from upstream — kept as-is per spec 0116
; Non-goals: existing 5 captures preserved).
(string) @string
(field_name) @attribute
(comment) @comment
(number) @number
(open_squiggly) @punctuation.bracket
(close_squiggly) @punctuation.bracket
(open_square) @punctuation.bracket
(close_square) @punctuation.bracket
(open_arrow) @punctuation.bracket
(close_arrow) @punctuation.bracket

; §1/§2 — extension_name/any_name get a distinct capture, separate from
; ordinary field_name. Declared after (field_name) @attribute above so
; last-match-wins precedence lets @type stand for extension_name/
; any_name's byte range (field_name: $ => choice(extension_name,
; any_name, identifier) has no other tokens of its own).
(extension_name) @type

(any_name
  (domain) @string.special.url
  (type_name) @type)

; §3 — string_escape gets its own capture, sibling to the enclosing
; string's @string (both fire on overlapping ranges by design).
(string_escape) @string.escape

; §4 — bare identifier scalar values. Blanket @constant declared first
; (schema-blind default: without a .proto schema, the grammar cannot
; tell an enum value name (KNOWN_ENUM_VALUE) from a bool/inf value
; handled below, or from a genuinely invalid/unknown scalar. @constant
; is chosen as the least-wrong default: enum-value-name identifiers are
; by far the more common case for a non-true/false/inf bare identifier
; in practice, and @constant is the closest standard capture
; semantically ("a named, unchanging value"). Declared first so the
; more specific patterns below can override it (tree-sitter's
; last-match-wins precedence is declaration order, not predicate
; specificity).
(scalar_value (identifier) @constant)
(scalar_value (signed_identifier) @constant)

((scalar_value (identifier) @boolean)
 (#any-of? @boolean "true" "false"))

; Narrowed from the historical unconditional @number pattern — @number
; now applies only to the inf/-inf identifier values it was actually
; meant for. Declared last (most specific) so it wins over both
; patterns above for these two exact values.
((scalar_value (identifier) @number)
 (#eq? @number "inf"))
((scalar_value (signed_identifier) @number)
 (#eq? @number "-inf"))

; §5 — delimiter punctuation.
[":" "," ";"] @punctuation.delimiter

; §6 — split @punctuation.bracket by context. Message body braces/
; angle-brackets are already covered by the blanket patterns above,
; unchanged (the "default" bracket kind). Square brackets are a single
; pair of named token rules reused across four different contexts
; (message_list, scalar_list, extension_name, any_name) — disambiguate
; through the parent node. These context-scoped patterns are declared
; after the blanket (open_square)/(close_square) @punctuation.bracket
; patterns above so the more specific .list/.extension captures win by
; last-match-wins declaration order.
(message_list (open_square) @punctuation.bracket.list)
(message_list (close_square) @punctuation.bracket.list)
(scalar_list (open_square) @punctuation.bracket.list)
(scalar_list (close_square) @punctuation.bracket.list)

(extension_name (open_square) @punctuation.bracket.extension)
(extension_name (close_square) @punctuation.bracket.extension)
(any_name (open_square) @punctuation.bracket.extension)
(any_name (close_square) @punctuation.bracket.extension)
