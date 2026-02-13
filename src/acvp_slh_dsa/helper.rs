/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use crate::acvp_slh_dsa::adrs::Adrs;
use crate::acvp_slh_dsa::slh_dsa_context::SlhContext;

// [cite: 2261] Algorithm 2: toInt(X, n)
pub fn to_int(x: &[u8], n: usize) -> u64 {
    let mut total = 0u64;
    for &byte in &x[..n] {
        total = (total << 8) + (byte as u64);
    }
    total
}

// [cite: 2290] Algorithm 4: base_2b(X, b, out_len)
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut out = vec![0u32; out_len];
    let mut in_idx = 0;
    let mut bits = 0;
    let mut total = 0u32; // Assuming b + 7 <= 32, which is true for standard params

    for item in out.iter_mut() {
        while bits < b {
            total = (total << 8) + (x[in_idx] as u32);
            in_idx += 1;
            bits += 8;
        }
        bits -= b;
        *item = (total >> bits) & ((1 << b) - 1);
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
