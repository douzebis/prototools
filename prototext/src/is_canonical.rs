// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `prototext is-canonical` (spec 0396): a per-file `canonical`/`anomalous`
//! verdict, and for an anomalous file one `label: count` line per anomaly
//! kind.
//!
//! The anomalies are the ones prototext already annotates in its decode
//! (spec 0226). This counts them from the annotated render — the same `#@`
//! comments protolens reads — rather than recomputing canonicity, so the two
//! cannot drift. Each annotation keyword maps to a plural, non-jargon label;
//! which keywords can appear depends on the type in force (S4).

/// One anomaly kind: the annotation keywords that stand for it, and the
/// label `is-canonical` prints. The order of this table is the order the
/// detail lines are printed in (S3), so output is stable.
struct Kind {
    /// Annotation keywords (the bare word, `: value` stripped) that count
    /// as this kind.
    keywords: &'static [&'static str],
    label: &'static str,
}

/// The anomaly kinds (spec 0396 S2), in print order. Encoding anomalies
/// first (checkable with no schema), then the type-revealed ones.
const KINDS: &[Kind] = &[
    Kind {
        keywords: &["tag_ohb", "etag_ohb"],
        label: "overhanging bytes in tags",
    },
    Kind {
        keywords: &["len_ohb"],
        label: "overhanging bytes in length prefixes",
    },
    Kind {
        keywords: &["val_ohb", "ohb"],
        label: "overhanging bytes in values",
    },
    Kind {
        keywords: &["packed_ohb"],
        label: "overhanging bytes in packed elements",
    },
    Kind {
        keywords: &["TAG_OOR", "ETAG_OOR"],
        label: "out-of-range field numbers",
    },
    Kind {
        keywords: &["INVALID_TAG_TYPE"],
        label: "invalid wire types",
    },
    Kind {
        keywords: &["TRUNCATED_MESSAGE"],
        label: "truncated messages",
    },
    Kind {
        keywords: &["TRUNCATED_BYTES"],
        label: "truncated fields",
    },
    Kind {
        keywords: &["neg", "truncated_neg", "packed_truncated_neg"],
        label: "non-canonical negative integers",
    },
    Kind {
        keywords: &["nan_bits"],
        label: "non-canonical NaN values",
    },
    Kind {
        keywords: &["packing_mismatch"],
        label: "packing mismatches",
    },
    Kind {
        keywords: &["TYPE_MISMATCH"],
        label: "wire/schema type mismatches",
    },
    Kind {
        keywords: &["ENUM_UNKNOWN"],
        label: "unknown enum values",
    },
    Kind {
        keywords: &["INVALID_STRING"],
        label: "invalid UTF-8 strings",
    },
    Kind {
        keywords: &["repeated_singular"],
        label: "repeated singular fields",
    },
];

/// Count each anomaly kind in an annotated render.
///
/// The render is prototext's own, with annotations on: every `#@` comment
/// holds `; `-separated items, each a bare keyword or `keyword: value`.
/// This tallies one per keyword occurrence — so two `val_ohb` on two
/// different fields count two, matching "how many fields are affected".
/// Returns the counts aligned with [`KINDS`].
pub fn count_kinds(annotated: &str) -> Vec<u64> {
    let mut counts = vec![0u64; KINDS.len()];
    for line in annotated.lines() {
        let Some((_, ann)) = line.split_once("#@") else {
            continue;
        };
        for item in ann.split(';') {
            let word = item.trim().split([':', ' ']).next().unwrap_or("").trim();
            if word.is_empty() {
                continue;
            }
            for (i, kind) in KINDS.iter().enumerate() {
                if kind.keywords.contains(&word) {
                    counts[i] += 1;
                    break;
                }
            }
        }
    }
    counts
}

/// The report for one file: its path, and the counts from [`count_kinds`].
/// `anomalous` is true when any count is non-zero.
pub struct FileReport {
    pub path: String,
    counts: Vec<u64>,
}

impl FileReport {
    pub fn from_annotated(path: String, annotated: &str) -> Self {
        FileReport {
            path,
            counts: count_kinds(annotated),
        }
    }

    pub fn anomalous(&self) -> bool {
        self.counts.iter().any(|&c| c > 0)
    }

    /// The block for this file (spec 0396 S3): `path: canonical`, or
    /// `path: anomalous` then one indented `label: count` line per kind
    /// present, in [`KINDS`] order.
    pub fn render(&self) -> String {
        if !self.anomalous() {
            return format!("{}: canonical", self.path);
        }
        let mut out = format!("{}: anomalous", self.path);
        for (i, kind) in KINDS.iter().enumerate() {
            if self.counts[i] > 0 {
                out.push_str(&format!("\n    {}: {}", kind.label, self.counts[i]));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_render_is_canonical() {
        let r = FileReport::from_annotated("x.pb".into(), "1: 1  #@ varint = 1");
        assert!(!r.anomalous());
        assert_eq!(r.render(), "x.pb: canonical");
    }

    #[test]
    fn overhang_and_truncation_are_counted_and_labeled() {
        let text = "\
1: 1  #@ varint; val_ohb: 1
2: 1  #@ varint; val_ohb: 1
3: \"ab\"  #@ TRUNCATED_BYTES; MISSING: 3";
        let r = FileReport::from_annotated("y.pb".into(), text);
        assert!(r.anomalous());
        assert_eq!(
            r.render(),
            "y.pb: anomalous\n    overhanging bytes in values: 2\n    truncated fields: 1"
        );
    }

    #[test]
    fn kinds_print_in_table_order() {
        // A truncated message (late in the table) and a tag overhang (early):
        // the tag overhang must come first.
        let text = "\
1: { }  #@ TRUNCATED_MESSAGE
2: 1  #@ int32 = 2; tag_ohb: 4";
        let r = FileReport::from_annotated("z.pb".into(), text);
        assert_eq!(
            r.render(),
            "z.pb: anomalous\n    overhanging bytes in tags: 1\n    truncated messages: 1"
        );
    }

    #[test]
    fn a_colon_value_does_not_split_the_keyword() {
        // `val_ohb: 3` must count as val_ohb, not as a bare `3`.
        let counts = count_kinds("1: 1  #@ varint; val_ohb: 3");
        let total: u64 = counts.iter().sum();
        assert_eq!(total, 1);
    }
}
