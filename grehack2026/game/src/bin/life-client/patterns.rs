// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The named starting patterns of `--pattern` (spec 0375 S5).

/// The live cells of a pattern, as rows where `#` is alive, or `None` for
/// an unknown name.
pub fn rows(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "glider" => &[".#.", "..#", "###"],
        "r-pentomino" => &[".##", "##.", ".#."],
        "gosper-gun" => &[
            "........................#...........",
            "......................#.#...........",
            "............##......##............##",
            "...........#...#....##............##",
            "##........#.....#...##..............",
            "##........#...#.##....#.#...........",
            "..........#.....#.......#...........",
            "...........#...#....................",
            "............##......................",
        ],
        _ => return None,
    })
}

pub const NAMES: &[&str] = &["glider", "r-pentomino", "gosper-gun"];

/// `pattern` drawn onto an empty `width` × `height` grid: centered, or at
/// the top left when it does not fit, and clipped to the grid.
pub fn place(pattern: &[&str], width: usize, height: usize) -> Vec<Vec<bool>> {
    let mut cells = vec![vec![false; width]; height];
    let (pw, ph) = (pattern.first().map_or(0, |r| r.len()), pattern.len());
    let (x0, y0) = (width.saturating_sub(pw) / 2, height.saturating_sub(ph) / 2);
    for (dy, row) in pattern.iter().enumerate() {
        for (dx, c) in row.chars().enumerate() {
            if c == '#' {
                if let Some(cell) = cells.get_mut(y0 + dy).and_then(|r| r.get_mut(x0 + dx)) {
                    *cell = true;
                }
            }
        }
    }
    cells
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_is_rectangular() {
        for name in NAMES {
            let rows = rows(name).unwrap();
            assert!(rows.iter().all(|r| r.len() == rows[0].len()), "{name}");
        }
    }

    #[test]
    fn a_glider_is_centered() {
        let cells = place(rows("glider").unwrap(), 5, 5);
        let live: Vec<_> = (0..5)
            .flat_map(|y| (0..5).map(move |x| (x, y)))
            .filter(|&(x, y)| cells[y][x])
            .collect();
        assert_eq!(live, [(2, 1), (3, 2), (1, 3), (2, 3), (3, 3)]);
    }

    #[test]
    fn a_pattern_larger_than_the_grid_is_clipped() {
        let cells = place(rows("gosper-gun").unwrap(), 10, 4);
        assert_eq!((cells.len(), cells[0].len()), (4, 10));
    }
}
