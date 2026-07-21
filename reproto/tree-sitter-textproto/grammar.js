// Vendored, locally-modified copy of upstream tree-sitter-textproto's
// grammar.js (pinned commit 568471b80fd8793d37ed01865d8c2208a9fefd1b:
// https://github.com/PorterAtGoogle/tree-sitter-textproto). See
// docs/specs/0121-tree-sitter-textproto-field-no-vendoring.md for why this
// is now vendored+modified rather than fetched-and-generated verbatim: a
// new `field_no` rule (cloned from `dec_int`'s own definition, not reused
// directly — a shared rule risks an LR table conflict between `field_no`'s
// structural position, inside `field_name`, and `dec_int`'s own, inside
// `number`) is added as a `field_name` alternative, so a bare decimal
// field number (protolens's own rendering convention for an
// unknown/unresolved field) parses as a valid `field_name` instead of
// triggering tree-sitter's error-recovery mode.

// https://protobuf.dev/reference/protobuf/textformat-spec/

module.exports = grammar({
  name: 'textproto',

  rules: {
    message: $ => repeat($.field),

    field: $ => choice($.message_field, $.scalar_field),

    message_field: $ => seq(
      $.field_name,
      optional(":"),
      choice($.message_value, $.message_list),
      optional(choice(";", ",")),
    ),

    scalar_field: $ => seq(
      $.field_name,
      ":",
      choice(
    $.scalar_value,
    $.scalar_list,
      ),
      optional(choice(";", ",")),
    ),

    message: $ => repeat1($.field),

    message_value: $ => choice(
      seq(
    $.open_squiggly,
    optional($.message),
    $.close_squiggly,
      ),
      seq(
    $.open_arrow,
    optional($.message),
    $.close_arrow,
      )
    ),

    message_list: $ => prec(2, seq(
      $.open_square,
      optional(
    seq(
      $.message_value,
      repeat(
        seq(
          ",",
          $.message_value,
        ),
      ),
    ),
      ),
      $.close_square,
    )),

    open_squiggly: $ => '{',
    close_squiggly: $ => '}',
    open_square: $ => '[',
    close_square: $ => ']',
    open_arrow: $ => '<',
    close_arrow: $ => '>',

    // Local modification (see file header): `$.field_no` is a new
    // alternative, not present upstream — protolens renders a field it
    // cannot resolve to a schema name as its bare decimal field number
    // (e.g. `1 { ... }`), which upstream's grammar rejects (only
    // `identifier`/`extension_name`/`any_name` are valid `field_name`s),
    // triggering tree-sitter's error-recovery mode and corrupting
    // highlight captures on neighboring siblings.
    field_name: $ => choice(
      $.extension_name,
      $.any_name,
      $.identifier,
      $.field_no,
    ),

    extension_name: $ => seq(
      $.open_square,
      $.type_name,
      $.close_square,
    ),

    any_name: $ => seq(
      $.open_square,
      $.domain,
      "/",
      $.type_name,
      $.close_square,
    ),

    type_name: $ => seq(
      $.identifier,
      repeat(choice(".", $.identifier)),
    ),
    domain: $ => seq(
      $.identifier,
      repeat(choice(".", $.identifier)),
    ),

    identifier: $ => /[A-Za-z_][A-Za-z0-9_]*/,
    signed_identifier: $ => seq(
      "-",
      $.identifier,
    ),

    // Local addition (see file header): cloned from `dec_int`'s own
    // definition below, deliberately not shared with it — `field_name`
    // and `number` occupy different structural positions in the grammar,
    // and reusing the same rule in both risked an LR table conflict.
    field_no: $ => choice(
      "0",
      /[1-9][0-9]*/,
    ),

    scalar_value: $ => choice(
      repeat1($.string),
      $.identifier,
      $.signed_identifier,
      $.number,
    ),

    scalar_list: $ => prec(1, seq(
      $.open_square,
      optional(
    seq(
      $.scalar_value,
      repeat(seq(",", $.scalar_value)),
    ),
      ),
      $.close_square,
    )),

    string: $ => choice(
      $.single_string,
      $.double_string,
    ),

    single_string: $ => seq(
      "'",
      repeat(choice(
    $.string_escape,
    $.single_string_contents,
      )),
      "'",
    ),

    double_string: $ => seq(
      '"',
      repeat(choice(
    $.string_escape,
    $.double_string_contents,
      )),
      '"',
    ),

    single_string_contents: $ => /[^\n'\\]+/,
    double_string_contents: $ => /[^\n"\\]+/,

    string_escape: $ => choice(
      "\\a",
      "\\b",
      "\\f",
      "\\n",
      "\\r",
      "\\t",
      "\\v",
      "\\?",
      "\\\"",
      "\\'",
      '\\"',
      seq("\\", $.oct, optional($.oct), optional($.oct)),
      seq("\\x", $.hex, optional($.hex)),
      seq("\\u", $.hex, $.hex, $.hex, $.hex),
      seq("\\U000", $.hex, $.hex, $.hex, $.hex, $.hex),
      seq("\\U010", $.hex, $.hex, $.hex, $.hex),
    ),

    oct: $ => /[0-7]/,
    hex: $ => /[0-9A-Fa-f]/,

    number: $ => choice(
      $.dec_int,
      $.oct_int,
      $.hex_int,
      seq(optional('-'), $.float),
      seq("-", $.dec_int),    // signed decimal int
      seq('-', $.oct_int),    // signed octal int
      seq('-', $.hex_int),    // signed hexidecimal int
    ),

    dec_int: $ => choice(
      "0",
      /[1-9][0-9]*/,
    ),
    oct_int: $ => /0[0-7]+/,
    hex_int: $ => /0[Xx][0-9A-Fa-f]+/,
    float_lit: $ => choice(
      seq(
    $.dec_int,
    $.exp
      ),
      seq(
    ".",
    $.frac_digits,
    optional($.exp)
      ),
      seq(
    $.dec_int,
    ".",
    optional($.frac_digits),
    optional($.exp)
      ),
    ),
    // Local fix: the `field_no` addition above (spec 0121) makes the
    // LALR automaton merge float_lit's post-"." state with an unrelated
    // field_no state, so plain (unprioritized) digit-run/exponent-lead
    // tokens here lose the lexer's ambiguity tie-break to field_no's
    // `/[1-9][0-9]*/` (or, for `exp`, to a plain `identifier`) — e.g.
    // "48.8566" parses as float_lit "48." + ERROR "8566", silently
    // dropping the fraction digits' `number` highlight past the
    // decimal point. `token(prec(N, ...))` gives these two tokens
    // lexer-level priority so they win that tie-break; named (not
    // anonymous inline /\d+/) so the fraction digits get their own
    // node distinct from `dec_int`.
    frac_digits: $ => token(prec(2, /\d+/)),
    exp: $ => seq(
      token(prec(2, /[Ee][-+]?/)),
      /\d+/,
    ),
    float: $ => choice(
      seq($.float_lit, optional(/[Ff]/)),
      seq($.dec_int, /[Ff]/),
    ),

    comment: $ => seq('#', /.*/)
  },

  extras: $ => [
    /\s/,
    $.comment,
  ],
  precedences: $ => [
    ["message_list", "scalar_list"],
  ],
});
