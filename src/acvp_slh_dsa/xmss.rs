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

use crate::acvp_slh_dsa::adrs::{Adrs, TREE, WOTS_HASH};
use crate::acvp_slh_dsa::helper::hash_h;
use crate::acvp_slh_dsa::slh_dsa_context::SlhContext;
use crate::acvp_slh_dsa::wots_plus::*;

// [cite: 2516] Algorithm 9: xmss_node(SK.seed, i, z, PK.seed, ADRS)
pub fn xmss_node(ctx: &SlhContext, i: u32, z: u32, adrs: &mut Adrs) -> Vec<u8> {
    if z == 0 {
        // [cite: 2367] Algorithm 6: wots_pkGen
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(i);
        wots_pk_gen(ctx, adrs)
    } else {
        let l_node = xmss_node(ctx, 2 * i, z - 1, adrs);
        let r_node = xmss_node(ctx, 2 * i + 1, z - 1, adrs);

        adrs.set_type_and_clear(TREE);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);

        let n = ctx.params.n;
        let mut input = vec![0u8; 2 * n];
        input[0..n].copy_from_slice(&l_node);
        input[n..2 * n].copy_from_slice(&r_node);
        hash_h(ctx, adrs, &input)
    }
}

// [cite: 2557] Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
pub fn xmss_sign(m: &[u8], ctx: &SlhContext, idx: u32, adrs: &mut Adrs) -> Vec<u8> {
    let n = ctx.params.n;
    let mut auth = vec![0u8; ctx.params.h_prime * n];

    // 1-4: Build authentication path
    for j in 0..ctx.params.h_prime {
        let k = (idx >> j) ^ 1;
        let node = xmss_node(ctx, k, j as u32, adrs);
        auth[j * n..(j + 1) * n].copy_from_slice(&node);
    }

    // 5-7: WOTS sign
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let sig = wots_sign(m, ctx, adrs);

    // 8: SIG_XMSS = sig || AUTH
    [sig, auth].concat()
}

// [cite: 2596] Algorithm 11: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)
pub fn xmss_pk_from_sig(
    idx: u32,
    sig_xmss: &[u8],
    m: &[u8],
    ctx: &SlhContext,
    adrs: &mut Adrs,
) -> Vec<u8> {
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);

    let n = ctx.params.n;
    // Extract WOTS signature and AUTH path
    let wots_len = ctx.params.len * n;
    let sig_wots = &sig_xmss[0..wots_len];
    let auth = &sig_xmss[wots_len..];

    // 5: node[0] = wots_pkFromSig
    let mut node = wots_pk_from_sig(sig_wots, m, ctx, adrs);

    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);

    // 8-18: Compute root
    for k in 0..ctx.params.h_prime {
        adrs.set_tree_height((k + 1) as u32);

        let auth_k = &auth[k * n..(k + 1) * n];
        let mut input = vec![0u8; 2 * n];

        if ((idx >> k) & 1) == 0 {
            adrs.set_tree_index(
                adrs.data[28..32]
                    .try_into()
                    .map(u32::from_be_bytes)
                    .unwrap()
                    / 2,
            );
            input[0..n].copy_from_slice(&node);
            input[n..].copy_from_slice(auth_k);
        } else {
            adrs.set_tree_index(
                (adrs.data[28..32]
                    .try_into()
                    .map(u32::from_be_bytes)
                    .unwrap()
                    - 1)
                    / 2,
            );
            input[0..n].copy_from_slice(auth_k);
            input[n..].copy_from_slice(&node);
        }
        node = hash_h(ctx, adrs, &input);
    }
    node
}
