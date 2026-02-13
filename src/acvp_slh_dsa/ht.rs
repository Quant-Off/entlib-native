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
use crate::acvp_slh_dsa::xmss::{xmss_pk_from_sig, xmss_sign};

// [cite: 2658] Algorithm 12: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
pub fn ht_sign(m: &[u8], ctx: &SlhContext, idx_tree: u64, idx_leaf: u32) -> Vec<u8> {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    // SIG_tmp = xmss_sign(M, SK.seed, idx_leaf, PK.seed, ADRS)
    let sig_tmp = xmss_sign(m, ctx, idx_leaf, &mut adrs);
    let mut sig_ht = sig_tmp.clone();

    // root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root = xmss_pk_from_sig(idx_leaf, &sig_tmp, m, ctx, &mut adrs);

    let mut curr_idx_tree = idx_tree;
    let mut curr_idx_leaf;

    // Loop layers
    for j in 1..ctx.params.d {
        curr_idx_leaf = (curr_idx_tree as u32) & ((1 << ctx.params.h_prime) - 1); // mod 2^h'
        curr_idx_tree = curr_idx_tree >> ctx.params.h_prime;

        adrs.set_layer_address(j as u32);
        adrs.set_tree_address(curr_idx_tree);

        let sig_layer = xmss_sign(&root, ctx, curr_idx_leaf, &mut adrs);
        sig_ht.extend_from_slice(&sig_layer);

        if j < ctx.params.d - 1 {
            root = xmss_pk_from_sig(curr_idx_leaf, &sig_layer, &root, ctx, &mut adrs);
        }
    }
    sig_ht
}
