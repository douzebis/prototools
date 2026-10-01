// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Prime factorization of a `u128` (spec 0382 S6): the client factors the
//! server's number with it, and the server checks the factors' primality.

/// The Miller-Rabin bases, and the trial divisors that precede them. These
/// 12 bases are deterministic below 3.3·10^24 (spec 0382 N3); above it the
/// test answers "probable prime".
const BASES: [u128; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

/// Trial division bound in `factorize`: rho is run only on what is left.
const TRIAL: u128 = 1000;

/// How many rho iterations between two polls of `keep_going` (spec 0382 S5).
const POLL: u32 = 1024;

/// `a * b mod m`, for `a, b < m`.
pub fn mul_mod(a: u128, b: u128, m: u128) -> u128 {
    if m <= u128::from(u64::MAX) {
        return a * b % m; // a, b < 2^64: the product fits
    }
    // The 256-bit product, as (hi, lo): hi reduced natively, then the bits
    // of lo shifted in one at a time.
    let (hi, lo) = widening_mul(a, b);
    let mut r = hi % m;
    for i in (0..128).rev() {
        let bit = (lo >> i) & 1;
        // r < m, so 2r + bit < 2m: at most one subtraction. 2r may overflow
        // u128; the carry then means "at least 2^128 > m".
        let (doubled, carry) = r.overflowing_add(r);
        let (next, carry2) = doubled.overflowing_add(bit);
        r = if carry || carry2 || next >= m {
            next.wrapping_sub(m)
        } else {
            next
        };
    }
    r
}

/// The full product `a * b`, as (high 128 bits, low 128 bits).
fn widening_mul(a: u128, b: u128) -> (u128, u128) {
    const LO: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & LO);
    let (b1, b0) = (b >> 64, b & LO);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    // The middle column: three terms below 2^64 each, so no overflow.
    let mid = (p00 >> 64) + (p01 & LO) + (p10 & LO);
    let lo = (p00 & LO) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// `base ^ exp mod m`.
pub fn pow_mod(mut base: u128, mut exp: u128, m: u128) -> u128 {
    let mut acc = 1 % m;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul_mod(acc, base, m);
        }
        base = mul_mod(base, base, m);
        exp >>= 1;
    }
    acc
}

/// Whether `n` is prime: deterministic below 3.3·10^24, probable above
/// (spec 0382 N3).
pub fn is_prime(n: u128) -> bool {
    if n < 2 {
        return false;
    }
    for p in BASES {
        if n.is_multiple_of(p) {
            return n == p;
        }
    }
    let s = (n - 1).trailing_zeros();
    let d = (n - 1) >> s;
    'bases: for a in BASES {
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// `(a + b) mod m`, for `a, b < m`, without overflowing.
fn add_mod(a: u128, b: u128, m: u128) -> u128 {
    if a >= m - b {
        a - (m - b)
    } else {
        a + b
    }
}

/// A non-trivial factor of the composite `n`, which has no factor below
/// `TRIAL` (Pollard rho, Brent's variant, the gcd batched over `POLL`
/// steps), or `None` once `keep_going` says to stop.
fn rho(n: u128, keep_going: &dyn Fn() -> bool) -> Option<u128> {
    for c in 1.. {
        let f = |x: u128| add_mod(mul_mod(x, x, n), c, n);
        let (mut x, mut y, mut ys) = (2u128, 2u128, 2u128);
        let (mut r, mut q, mut g) = (1u64, 1u128, 1u128);
        while g == 1 {
            x = y;
            for i in 0..r {
                if i % u64::from(POLL) == 0 && !keep_going() {
                    return None;
                }
                y = f(y);
            }
            let mut k = 0;
            while k < r && g == 1 {
                if !keep_going() {
                    return None;
                }
                ys = y;
                for _ in 0..u64::from(POLL).min(r - k) {
                    y = f(y);
                    q = mul_mod(q, x.abs_diff(y), n);
                }
                g = gcd(q, n);
                k += u64::from(POLL);
            }
            r *= 2;
        }
        if g == n {
            // The batch overshot: replay it one step at a time.
            loop {
                ys = f(ys);
                g = gcd(x.abs_diff(ys), n);
                if g > 1 {
                    break;
                }
            }
        }
        if g != n {
            return Some(g);
        }
        // This polynomial cycled without splitting n: try the next one.
    }
    unreachable!("some c splits a composite")
}

/// The integer `k`-th root of `n`, rounded down.
fn iroot(n: u128, k: u32) -> u128 {
    // A float first guess, then corrected both ways: f64 has 53 bits.
    let mut r = (n as f64).powf(1.0 / f64::from(k)) as u128;
    let fits = |r: u128| r.checked_pow(k).is_some_and(|p| p <= n);
    while !fits(r) {
        r -= 1;
    }
    while fits(r + 1) {
        r += 1;
    }
    r
}

/// `n` as `r^k` with `k` as large as possible (`k` = 1 when `n` is no
/// perfect power). Rho finds a factor `p` in about √p steps, so `p^2` with
/// `p` near 2^61 would take 2^30 of them; a root takes none.
fn perfect_power(n: u128) -> (u128, u32) {
    for k in (2..=127).rev() {
        let r = iroot(n, k);
        if r > 1 && r.pow(k) == n {
            return (r, k);
        }
    }
    (n, 1)
}

/// The prime factorization of `n` ≥ 2, primes ascending with their
/// exponents, or `None` if `keep_going` returned false first (spec 0382 S5).
pub fn factorize(n: u128, keep_going: &dyn Fn() -> bool) -> Option<Vec<(u128, u32)>> {
    let mut primes = Vec::new();
    let mut rest = n;
    let mut p = 2;
    while p < TRIAL && p * p <= rest {
        while rest.is_multiple_of(p) {
            primes.push(p);
            rest /= p;
        }
        p += if p == 2 { 1 } else { 2 };
    }
    let mut todo = vec![rest];
    while let Some(m) = todo.pop() {
        if m == 1 {
            continue;
        }
        if is_prime(m) {
            primes.push(m);
            continue;
        }
        match perfect_power(m) {
            (r, k) if k > 1 => todo.extend(std::iter::repeat_n(r, k as usize)),
            _ => {
                let d = rho(m, keep_going)?;
                todo.push(d);
                todo.push(m / d);
            }
        }
    }
    primes.sort_unstable();
    let mut out: Vec<(u128, u32)> = Vec::new();
    for p in primes {
        match out.last_mut() {
            Some((q, e)) if *q == p => *e += 1,
            _ => out.push((p, 1)),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always() -> bool {
        true
    }

    fn naive_is_prime(n: u128) -> bool {
        n >= 2
            && (2..)
                .take_while(|d| d * d <= n)
                .all(|d| !n.is_multiple_of(d))
    }

    fn product(f: &[(u128, u32)]) -> u128 {
        f.iter().map(|&(p, e)| p.pow(e)).product()
    }

    #[test]
    fn mul_mod_matches_the_wide_product() {
        // A large odd modulus, and (m-1)^2 = m^2 - 2m + 1 ≡ 1 (mod m).
        let m = u128::MAX - 158;
        assert_eq!(mul_mod(m - 1, m - 1, m), 1);
        assert_eq!(mul_mod(m - 1, 2, m), m - 2);
        let (hi, lo) = widening_mul(u128::MAX, u128::MAX);
        assert_eq!((hi, lo), (u128::MAX - 1, 1));
        // A small modulus takes the native path.
        assert_eq!(mul_mod(6, 7, 10), 2);
    }

    #[test]
    fn is_prime_matches_trial_division() {
        for n in 0..20_000 {
            assert_eq!(is_prime(n), naive_is_prime(n), "{n}");
        }
    }

    #[test]
    fn is_prime_knows_mersenne_primes_and_pseudoprimes() {
        for e in [61, 89, 107, 127] {
            assert!(is_prime((1u128 << e) - 1), "2^{e}-1");
        }
        assert!(!is_prime((1u128 << 67) - 1)); // 193707721 × 761838257287
        for n in [
            561u128,
            1105,
            1729,
            3_215_031_751,
            3_825_123_056_546_413_051,
        ] {
            assert!(!is_prime(n), "{n}");
        }
    }

    #[test]
    fn factorize_matches_trial_division() {
        for n in 2..10_000u128 {
            let f = factorize(n, &always).unwrap();
            assert_eq!(product(&f), n, "{n}");
            assert!(f.iter().all(|&(p, _)| naive_is_prime(p)), "{n}: {f:?}");
            assert!(f.windows(2).all(|w| w[0].0 < w[1].0), "{n}: {f:?}");
        }
    }

    #[test]
    fn perfect_powers_are_found() {
        assert_eq!(perfect_power(1 << 127), (2, 127));
        assert_eq!(perfect_power(1009 * 1009 * 1009), (1009, 3));
        assert_eq!(perfect_power(36), (6, 2));
        assert_eq!(perfect_power(1010), (1010, 1));
        assert_eq!(perfect_power(u128::MAX), (u128::MAX, 1));
        assert_eq!(iroot(u128::MAX, 2), u128::from(u64::MAX));
    }

    #[test]
    fn factorize_handles_large_numbers() {
        assert_eq!(factorize(1 << 127, &always).unwrap(), vec![(2, 127)]);
        let m31 = (1u128 << 31) - 1;
        let m61 = (1u128 << 61) - 1;
        assert_eq!(
            factorize(m31 * m61, &always).unwrap(),
            vec![(m31, 1), (m61, 1)]
        );
        assert_eq!(factorize(m61 * m61, &always).unwrap(), vec![(m61, 2)]);
        assert_eq!(factorize(m31.pow(4), &always).unwrap(), vec![(m31, 4)]);
        assert_eq!(
            factorize(3 * 3 * 1009 * 1009, &always).unwrap(),
            vec![(3, 2), (1009, 2)]
        );
        let max = factorize(u128::MAX, &always).unwrap();
        assert_eq!(product(&max), u128::MAX);
        assert!(max.iter().all(|&(p, _)| is_prime(p)));
    }

    #[test]
    fn factorize_stops_when_told() {
        let m61 = (1u128 << 61) - 1;
        let m31 = (1u128 << 31) - 1;
        // No small factor and no perfect power: rho must run, so it polls.
        assert_eq!(factorize(m31 * m61 * 3, &|| false), None);
    }
}
