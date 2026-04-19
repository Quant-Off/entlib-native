use crate::field::{Q, add_q, mul_q, sub_q};

pub(crate) const N: usize = 256;

// FIPS 203: q=3329, primitive 256th root of unity ζ=17.

const fn pow_mod_q(base: i32, mut exp: usize) -> i32 {
    let mut result = 1i32;
    let mut b = base;
    let q = Q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as i64 * b as i64).rem_euclid(q as i64)) as i32;
        }
        exp >>= 1;
        b = ((b as i64 * b as i64).rem_euclid(q as i64)) as i32;
    }
    result
}

/// 7-bit reversal of k.
const fn brv7(mut k: usize) -> usize {
    let mut r = 0usize;
    let mut i = 0;
    while i < 7 {
        r = (r << 1) | (k & 1);
        k >>= 1;
        i += 1;
    }
    r
}

// ZETAS[i] = 17^{brv7(i+1)} mod q, for i=0..126 (127 values).
// NTT uses ZETAS[k] for k=0..126 (ascending); INTT uses -ZETAS[k] descending.
pub(crate) const ZETAS: [i32; 127] = {
    let mut z = [0i32; 127];
    let mut i = 0usize;
    while i < 127 {
        z[i] = pow_mod_q(17, brv7(i + 1));
        i += 1;
    }
    z
};

// MULZETAS[i] = 17^{2·brv7(i)+1} mod q, for i=0..127 (128 values).
// Used in MultiplyNTTs (FIPS 203 Algorithm 10).
pub(crate) const MULZETAS: [i32; 128] = {
    let mut g = [0i32; 128];
    let mut i = 0usize;
    while i < 128 {
        g[i] = pow_mod_q(17, 2 * brv7(i) + 1);
        i += 1;
    }
    g
};

// 128^{-1} mod q: since 3329 = 26·128 + 1 → 128^{-1} ≡ -26 ≡ 3303 (mod 3329).
const INV_128: i32 = 3303;

/// FIPS 203 Algorithm 8: NTT.
/// Input/output coefficients in [0, q-1].
pub(crate) fn ntt(f: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = mul_q(zeta, f[j + len]);
                f[j + len] = sub_q(f[j], t);
                f[j] = add_q(f[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// FIPS 203 Algorithm 10: NTT^{-1}.
/// Input/output coefficients in [0, q-1].
pub(crate) fn intt(f: &mut [i32; N]) {
    let mut k = 126usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k = k.saturating_sub(1);
            for j in start..start + len {
                let t = f[j];
                f[j] = add_q(t, f[j + len]);
                f[j + len] = mul_q(zeta, sub_q(f[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for coeff in f.iter_mut() {
        *coeff = mul_q(*coeff, INV_128);
    }
}

/// FIPS 203 Algorithm 11: BaseMul.
/// Multiplies two degree-1 polynomials in Z_q[X]/(X^2 - gamma).
#[inline(always)]
pub(crate) fn base_mul(a0: i32, a1: i32, b0: i32, b1: i32, gamma: i32) -> (i32, i32) {
    let c0 = add_q(mul_q(a0, b0), mul_q(mul_q(a1, b1), gamma));
    let c1 = add_q(mul_q(a0, b1), mul_q(a1, b0));
    (c0, c1)
}

/// FIPS 203 Algorithm 10: MultiplyNTTs.
pub(crate) fn multiply_ntts(f: &[i32; N], g: &[i32; N]) -> [i32; N] {
    let mut h = [0i32; N];
    for i in 0..128 {
        let (h0, h1) = base_mul(f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], MULZETAS[i]);
        h[2 * i] = h0;
        h[2 * i + 1] = h1;
    }
    h
}
