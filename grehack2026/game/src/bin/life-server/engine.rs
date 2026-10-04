// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! One generation of a life-like automaton (spec 0375 S4), and the checks
//! a request must pass first. Only the server has this (spec 0375 N4).

use life::pb::{CellState, Grid, Range, Row, Rules, Topology};

/// The largest grid the server accepts, in either dimension.
pub const MAX_SIDE: usize = 512;

/// Conway's rules, used for whatever a request leaves out.
pub const CONWAY_BIRTH: Range = Range { min: 3, max: 3 };
pub const CONWAY_SURVIVAL: Range = Range { min: 2, max: 3 };

/// Why a request is refused; the message goes back as `INVALID_ARGUMENT`.
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

/// The rules a request asks for, with Conway's filling in what is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub birth: (u32, u32),
    pub survival: (u32, u32),
    pub torus: bool,
}

pub fn resolve(rules: Option<&Rules>) -> Result<Resolved, Invalid> {
    let default = Rules::default();
    let rules = rules.unwrap_or(&default);
    let range = |r: Range, what: &str| -> Result<(u32, u32), Invalid> {
        if r.min > r.max {
            return Err(Invalid(format!("{what}: min {} > max {}", r.min, r.max)));
        }
        if r.max > 8 {
            return Err(Invalid(format!(
                "{what}: max {} > 8, the most neighbors a cell has",
                r.max
            )));
        }
        Ok((r.min, r.max))
    };
    let torus = match Topology::try_from(rules.topology) {
        Ok(Topology::Bounded) => false,
        Ok(Topology::Torus) => true,
        Err(_) => return Err(Invalid(format!("unknown topology {}", rules.topology))),
    };
    Ok(Resolved {
        birth: range(rules.birth.unwrap_or(CONWAY_BIRTH), "birth")?,
        survival: range(rules.survival.unwrap_or(CONWAY_SURVIVAL), "survival")?,
        torus,
    })
}

/// The grid as booleans, after checking it is rectangular, within
/// [`MAX_SIDE`], and made of known cell states.
pub fn cells(grid: Option<&Grid>) -> Result<Vec<Vec<bool>>, Invalid> {
    let rows = grid.map(|g| &g.rows[..]).unwrap_or_default();
    if rows.len() > MAX_SIDE {
        return Err(Invalid(format!("{} rows > {MAX_SIDE}", rows.len())));
    }
    let width = rows.first().map_or(0, |r| r.cells.len());
    if width > MAX_SIDE {
        return Err(Invalid(format!("{width} columns > {MAX_SIDE}")));
    }
    rows.iter()
        .enumerate()
        .map(|(y, row)| {
            if row.cells.len() != width {
                return Err(Invalid(format!(
                    "row {y} has {} cells, row 0 has {width}",
                    row.cells.len()
                )));
            }
            row.cells
                .iter()
                .enumerate()
                .map(|(x, &c)| match CellState::try_from(c) {
                    Ok(CellState::Dead) => Ok(false),
                    Ok(CellState::Alive) => Ok(true),
                    Err(_) => Err(Invalid(format!("unknown cell state {c} at ({x}, {y})"))),
                })
                .collect()
        })
        .collect()
}

/// The next generation.
pub fn step(cells: &[Vec<bool>], rules: &Resolved) -> Vec<Vec<bool>> {
    let height = cells.len();
    let width = cells.first().map_or(0, Vec::len);
    let alive = |x: isize, y: isize| -> bool {
        let (w, h) = (width as isize, height as isize);
        let (x, y) = if rules.torus {
            (x.rem_euclid(w), y.rem_euclid(h))
        } else if x < 0 || y < 0 || x >= w || y >= h {
            return false;
        } else {
            (x, y)
        };
        cells[y as usize][x as usize]
    };
    let within = |n: u32, (min, max): (u32, u32)| min <= n && n <= max;
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| {
                    let (x, y) = (x as isize, y as isize);
                    let n = [
                        (-1, -1),
                        (0, -1),
                        (1, -1),
                        (-1, 0),
                        (1, 0),
                        (-1, 1),
                        (0, 1),
                        (1, 1),
                    ]
                    .iter()
                    .filter(|(dx, dy)| alive(x + dx, y + dy))
                    .count() as u32;
                    if alive(x, y) {
                        within(n, rules.survival)
                    } else {
                        within(n, rules.birth)
                    }
                })
                .collect()
        })
        .collect()
}

/// Booleans back to the wire.
pub fn grid(cells: &[Vec<bool>]) -> Grid {
    Grid {
        rows: cells
            .iter()
            .map(|row| Row {
                cells: row
                    .iter()
                    .map(|&c| {
                        if c {
                            CellState::Alive as i32
                        } else {
                            CellState::Dead as i32
                        }
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONWAY: Resolved = Resolved {
        birth: (3, 3),
        survival: (2, 3),
        torus: false,
    };

    /// `#` is alive, anything else dead; one string per row.
    fn parse(rows: &[&str]) -> Vec<Vec<bool>> {
        rows.iter()
            .map(|r| r.chars().map(|c| c == '#').collect())
            .collect()
    }

    fn run(mut cells: Vec<Vec<bool>>, rules: &Resolved, n: usize) -> Vec<Vec<bool>> {
        for _ in 0..n {
            cells = step(&cells, rules);
        }
        cells
    }

    #[test]
    fn a_blinker_oscillates() {
        let a = parse(&[".....", "..#..", "..#..", "..#..", "....."]);
        let b = parse(&[".....", ".....", ".###.", ".....", "....."]);
        assert_eq!(step(&a, &CONWAY), b);
        assert_eq!(step(&b, &CONWAY), a);
    }

    #[test]
    fn a_block_is_stable() {
        let block = parse(&["....", ".##.", ".##.", "...."]);
        assert_eq!(step(&block, &CONWAY), block);
    }

    #[test]
    fn a_glider_on_a_square_torus_comes_back() {
        let w = 8;
        let mut start = vec![vec![false; w]; w];
        for (x, y) in [(1, 0), (2, 1), (0, 2), (1, 2), (2, 2)] {
            start[y][x] = true;
        }
        let torus = Resolved {
            torus: true,
            ..CONWAY
        };
        assert_ne!(run(start.clone(), &torus, 4), start, "it moves");
        assert_eq!(run(start.clone(), &torus, 4 * w), start);
    }

    #[test]
    fn a_bounded_edge_is_dead() {
        // A blinker against the edge loses the cell outside the grid.
        let a = parse(&["#..", "#..", "#.."]);
        assert_eq!(step(&a, &CONWAY), parse(&["...", "##.", "..."]));
    }

    #[test]
    fn the_birth_range_is_the_requests() {
        // The center has six live neighbors: dead under Conway, born under
        // birth 6-6.
        let six = Resolved {
            birth: (6, 6),
            ..CONWAY
        };
        let a = parse(&["###", "#.#", "#.."]);
        assert!(!step(&a, &CONWAY)[1][1]);
        assert!(step(&a, &six)[1][1]);
    }

    #[test]
    fn absent_rules_mean_conway() {
        assert_eq!(resolve(None), Ok(CONWAY));
        let partial = Rules {
            birth: Some(Range { min: 3, max: 6 }),
            ..Default::default()
        };
        assert_eq!(
            resolve(Some(&partial)),
            Ok(Resolved {
                birth: (3, 6),
                ..CONWAY
            })
        );
    }

    #[test]
    fn bad_rules_are_refused() {
        let with = |birth: Range| Rules {
            birth: Some(birth),
            ..Default::default()
        };
        assert!(resolve(Some(&with(Range { min: 4, max: 3 }))).is_err());
        assert!(resolve(Some(&with(Range { min: 3, max: 9 }))).is_err());
        let topology = Rules {
            topology: 7,
            ..Default::default()
        };
        assert!(resolve(Some(&topology)).is_err());
    }

    #[test]
    fn bad_grids_are_refused() {
        let row = |cells: Vec<i32>| Row { cells };
        let ragged = Grid {
            rows: vec![row(vec![0, 1]), row(vec![0])],
        };
        assert!(cells(Some(&ragged)).is_err());
        let unknown = Grid {
            rows: vec![row(vec![0, 2])],
        };
        assert!(cells(Some(&unknown)).is_err());
        let tall = Grid {
            rows: vec![row(vec![0]); MAX_SIDE + 1],
        };
        assert!(cells(Some(&tall)).is_err());
        let wide = Grid {
            rows: vec![row(vec![0; MAX_SIDE + 1])],
        };
        assert!(cells(Some(&wide)).is_err());
        assert_eq!(cells(None), Ok(vec![]));
    }

    #[test]
    fn the_wire_round_trips() {
        let a = parse(&["#.", ".#"]);
        assert_eq!(cells(Some(&grid(&a))), Ok(a));
    }
}
