// SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The floor an inferred root type's score must reach (spec 0389).
//!
//! Shared by protolens and prototext so that both tools agree about the same
//! blob (G3). A score is matches minus weighted penalties
//! ([`EntryScore::score`](super::EntryScore::score)), so a negative score
//! means the type contradicts the bytes more than it explains them; hence
//! the default floor of 0.

use std::fmt;
use std::str::FromStr;

/// The lowest score an inferred root type may have and still be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinScore {
    /// Use the winner only if its score is at least this.
    AtLeast(i64),
    /// No floor: any untied winner is used, whatever its score.
    Any,
}

impl Default for MinScore {
    fn default() -> Self {
        MinScore::AtLeast(0)
    }
}

impl MinScore {
    /// Whether a winner with this `score` clears the floor.
    pub fn admits(self, score: i64) -> bool {
        match self {
            MinScore::AtLeast(floor) => score >= floor,
            MinScore::Any => true,
        }
    }
}

impl FromStr for MinScore {
    type Err = String;

    /// `any`, or an integer, negative allowed (spec 0389 S2).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "any" {
            return Ok(MinScore::Any);
        }
        s.parse::<i64>()
            .map(MinScore::AtLeast)
            .map_err(|_| format!("'{s}' is neither an integer nor 'any'"))
    }
}

impl fmt::Display for MinScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MinScore::AtLeast(floor) => write!(f, "{floor}"),
            MinScore::Any => f.write_str("any"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MinScore;

    #[test]
    fn parses_integers_negative_ones_and_any() {
        assert_eq!("0".parse(), Ok(MinScore::AtLeast(0)));
        assert_eq!("-100".parse(), Ok(MinScore::AtLeast(-100)));
        assert_eq!("250".parse(), Ok(MinScore::AtLeast(250)));
        assert_eq!("any".parse(), Ok(MinScore::Any));
        assert!("abc".parse::<MinScore>().is_err());
        assert!("".parse::<MinScore>().is_err());
    }

    #[test]
    fn the_floor_itself_is_admitted() {
        assert!(MinScore::AtLeast(0).admits(0));
        assert!(!MinScore::AtLeast(0).admits(-1));
        assert!(MinScore::AtLeast(-100).admits(-55));
        assert!(MinScore::Any.admits(i64::MIN));
    }

    #[test]
    fn the_default_is_zero() {
        assert_eq!(MinScore::default(), MinScore::AtLeast(0));
        assert_eq!(MinScore::default().to_string(), "0");
        assert_eq!(MinScore::Any.to_string(), "any");
    }
}
