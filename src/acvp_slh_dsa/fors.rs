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

use crate::acvp_slh_dsa::adrs::{Adrs, FORS_PRF, FORS_ROOTS};
use crate::acvp_slh_dsa::helper::{base_2b, hash_h, hash_t_l};
use crate::acvp_slh_dsa::slh_dsa_context::SlhContext;

// [cite: 2755] Algorithm 14: fors_skGen(SK.seed, PK.seed, ADRS, idx)
pub fn fors_sk_gen(ctx: &SlhContext, adrs: &Adrs, idx: u32) -> Vec<u8> {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair_address(adrs.data[20..24].try_into().map(u32::from_be_bytes).unwrap());
    sk_adrs.set_tree_index(idx);
    ctx.prf_addr(&sk_adrs)
}

// [cite: 2778] Algorithm 15: fors_node(SK.seed, i, z, PK.seed, ADRS)
pub fn fors_node(ctx: &SlhContext, i: u32, z: u32, adrs: &mut Adrs) -> Vec<u8> {
    if z == 0 {
        let sk = fors_sk_gen(ctx, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        ctx.f(adrs, &sk)
    } else {
        let l_node = fors_node(ctx, 2 * i, z - 1, adrs);
        let r_node = fors_node(ctx, 2 * i + 1, z - 1, adrs);

        adrs.set_tree_height(z);
        adrs.set_tree_index(i);

        let n = ctx.params.n;
        let mut input = vec![0u8; 2 * n];
        input[0..n].copy_from_slice(&l_node);
        input[n..].copy_from_slice(&r_node);
        hash_h(ctx, adrs, &input)
    }
}

// [cite: 2817] Algorithm 16: fors_sign(md, SK.seed, PK.seed, ADRS)
pub fn fors_sign(md: &[u8], ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    // 1: SIG_FORS = NULL (implicit Vec)
    let mut sig_fors = Vec::new();

    // 2: indices = base_2b(md, a, k)
    let indices = base_2b(md, ctx.params.a, ctx.params.k);

    // 3: Loop k times
    for i in 0..ctx.params.k {
        let idx = indices[i];

        // 4: Get secret key value
        let sk = fors_sk_gen(ctx, adrs, (i as u32) * (1 << ctx.params.a) + idx);
        sig_fors.extend_from_slice(&sk);

        // 5-9: Compute auth path
        for j in 0..ctx.params.a {
            let s_node = (indices[i] >> j) ^ 1;
            let auth_val = fors_node(ctx, (i as u32) * (1 << (ctx.params.a - j)) + s_node, j as u32, adrs);
            sig_fors.extend_from_slice(&auth_val);
        }
    }
    sig_fors
}

// [cite: 2855] Algorithm 17: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
pub fn fors_pk_from_sig(sig_fors: &[u8], md: &[u8], ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    let indices = base_2b(md, ctx.params.a, ctx.params.k);
    let n = ctx.params.n;
    let mut root = vec![0u8; ctx.params.k * n];

    let t = 1 << ctx.params.a; // t = 2^a
    let elem_size = n * (ctx.params.a + 1); // sk (N) + auth path (A * N)

    for i in 0..ctx.params.k {
        let offset = i * elem_size;
        let sk = &sig_fors[offset..offset + n];

        adrs.set_tree_height(0);
        let idx_leaf = (i as u32) * t + indices[i];
        adrs.set_tree_index(idx_leaf);

        let mut node_0 = ctx.f(adrs, sk);

        let auth_base = offset + n;
        for j in 0..ctx.params.a {
            let auth_node = &sig_fors[auth_base + j * n..auth_base + (j + 1) * n];
            adrs.set_tree_height((j + 1) as u32);

            // Logic for tree index update
            let current_idx = indices[i] >> j; // leaf index shifted
            if (current_idx % 2) == 0 {
                adrs.set_tree_index((adrs.data[28..32].try_into().map(u32::from_be_bytes).unwrap()) / 2);
                let mut input = vec![0u8; 2 * n];
                input[0..n].copy_from_slice(&node_0);
                input[n..].copy_from_slice(auth_node);
                node_0 = hash_h(ctx, adrs, &input);
            } else {
                adrs.set_tree_index((adrs.data[28..32].try_into().map(u32::from_be_bytes).unwrap() - 1) / 2);
                let mut input = vec![0u8; 2 * n];
                input[0..n].copy_from_slice(auth_node);
                input[n..].copy_from_slice(&node_0);
                node_0 = hash_h(ctx, adrs, &input);
            }
        }
        root[i * n..(i + 1) * n].copy_from_slice(&node_0);
    }

    let mut fors_pk_adrs = *adrs;
    fors_pk_adrs.set_type_and_clear(FORS_ROOTS);
    fors_pk_adrs.set_key_pair_address(adrs.data[20..24].try_into().map(u32::from_be_bytes).unwrap());

    hash_t_l(ctx, &fors_pk_adrs, &root)
}