// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

pub fn hello() -> &'static str {
    "hello"
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hello() {
        assert_eq!(super::hello(), "hello");
    }
}
