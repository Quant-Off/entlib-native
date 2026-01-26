use crate::acvp_slh_dsa::adrs::Adrs;
use crate::acvp_slh_dsa::slh_dsa_context::SlhContext;

// [cite: 2261] Algorithm 2: toInt(X, n)
pub fn to_int(x: &[u8], n: usize) -> u64 {
    let mut total = 0u64;
    for i in 0..n {
        total = (total << 8) + (x[i] as u64);
    }
    total
}

// [cite: 2290] Algorithm 4: base_2b(X, b, out_len)
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut out = vec![0u32; out_len];
    let mut in_idx = 0;
    let mut bits = 0;
    let mut total = 0u32; // Assuming b + 7 <= 32, which is true for standard params

    for i in 0..out_len {
        while bits < b {
            total = (total << 8) + (x[in_idx] as u32);
            in_idx += 1;
            bits += 8;
        }
        bits -= b;
        out[i] = (total >> bits) & ((1 << b) - 1);
    }
    out
}

// T_l(PK.seed, ADRS, M) - delegates to SlhContext which handles SHAKE/SHA2
pub fn hash_t_l(ctx: &SlhContext, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
    ctx.t_l(adrs, m)
}

// H(PK.seed, ADRS, M) - delegates to SlhContext which handles SHAKE/SHA2
pub fn hash_h(ctx: &SlhContext, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
    ctx.h(adrs, m)
}