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

use crate::acvp_slh_dsa::adrs::{Adrs, WOTS_PK, WOTS_PRF};
use crate::acvp_slh_dsa::helper::{base_2b, hash_t_l};
use crate::acvp_slh_dsa::slh_dsa_context::SlhContext;
use crate::acvp_slh_dsa::slh_dsa_params::to_byte;

//  Algorithm 6: wots_pkGen(SK.seed, PK.seed, ADRS)
// Generates a WOTS+ public key.
pub fn wots_pk_gen(ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    // 1: skADRS = ADRS
    let mut sk_adrs = *adrs;

    // 2: skADRS.setTypeAndClear(WOTS_PRF)
    // 주의: setTypeAndClear는 ADRS의 마지막 12바이트(인덱스 20~32)를 0으로 초기화하므로,
    // KeyPairAddress(인덱스 20~24)가 지워집니다. 따라서 이를 백업해두거나 복구해야 합니다.
    // 현재 Adrs 구조체 구현상 getter가 없으므로 직접 바이트에서 추출합니다.
    let kp_addr_bytes: [u8; 4] = adrs.data[20..24].try_into().unwrap();
    let kp_addr = u32::from_be_bytes(kp_addr_bytes);

    sk_adrs.set_type_and_clear(WOTS_PRF);

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_adrs.set_key_pair_address(kp_addr);

    let n = ctx.params.n;
    let mut tmp = vec![0u8; ctx.params.len * n];

    // 4: for i from 0 to len - 1 do
    for i in 0..ctx.params.len {
        // 5: skADRS.setChainAddress(i)
        sk_adrs.set_chain_address(i as u32);

        // 6: sk = PRF(PK.seed, SK.seed, skADRS)
        let sk = ctx.prf_addr(&sk_adrs);

        // 7: ADRS.setChainAddress(i)
        adrs.set_chain_address(i as u32);

        // 8: tmp[i] = chain(sk, 0, w-1, PK.seed, ADRS)
        let val = chain(&sk, 0, (ctx.params.w as u32) - 1, ctx, adrs);
        tmp[i * n..(i + 1) * n].copy_from_slice(&val);
    }

    // 10: wotspkADRS = ADRS
    let mut wots_pk_adrs = *adrs;

    // 11: wotspkADRS.setTypeAndClear(WOTS_PK)
    wots_pk_adrs.set_type_and_clear(WOTS_PK);

    // 12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    wots_pk_adrs.set_key_pair_address(kp_addr);

    // 13: pk = T_len(PK.seed, wotspkADRS, tmp)
    hash_t_l(ctx, &wots_pk_adrs, &tmp)
}

// [cite: 2350] Algorithm 5: chain(X, i, s, PK.seed, ADRS)
pub fn chain(x: &[u8], i: u32, s: u32, ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    if s == 0 {
        return x.to_vec();
    }
    let mut tmp = x.to_vec();
    for j in i..(i + s) {
        adrs.set_hash_address(j);
        tmp = ctx.f(adrs, &tmp);
    }
    tmp
}

// [cite: 2414] Algorithm 7: wots_sign(M, SK.seed, PK.seed, ADRS)
pub fn wots_sign(m: &[u8], ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    let mut csum = 0u32;
    // 2: msg = base_2b(M, lg_w, len1)
    let msg_base_w = base_2b(m, ctx.params.lg_w, ctx.params.len1);

    // 3-5: Compute checksum
    for val in &msg_base_w {
        csum += (ctx.params.w as u32) - 1 - val;
    }

    // 6: csum left shift
    csum = csum << ((8 - ((ctx.params.len2 * ctx.params.lg_w) % 8)) % 8);

    // 7: msg = msg || base_2b(toByte(csum), lg_w, len2)
    let len2_bytes = (ctx.params.len2 * ctx.params.lg_w + 7) / 8;
    let csum_bytes = to_byte(csum, len2_bytes);
    let csum_base_w = base_2b(&csum_bytes, ctx.params.lg_w, ctx.params.len2);

    let full_msg = [msg_base_w, csum_base_w].concat();

    let n = ctx.params.n;
    let mut sig = vec![0u8; ctx.params.len * n];
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(
        adrs.data[20..24]
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0),
    ); // Simplified extraction

    for i in 0..ctx.params.len {
        sk_adrs.set_chain_address(i as u32);
        // 13: sk = PRF(PK.seed, SK.seed, skADRS)
        let sk = ctx.prf_addr(&sk_adrs);

        adrs.set_chain_address(i as u32);
        // 15: sig[i] = chain(sk, 0, msg[i], PK.seed, ADRS)
        let sig_i = chain(&sk, 0, full_msg[i], ctx, adrs);
        sig[i * n..(i + 1) * n].copy_from_slice(&sig_i);
    }
    sig
}

// [cite: 2457] Algorithm 8: wots_pkFromSig(sig, M, PK.seed, ADRS)
pub fn wots_pk_from_sig(sig: &[u8], m: &[u8], ctx: &SlhContext, adrs: &mut Adrs) -> Vec<u8> {
    let mut csum = 0u32;
    let msg_base_w = base_2b(m, ctx.params.lg_w, ctx.params.len1);

    for val in &msg_base_w {
        csum += (ctx.params.w as u32) - 1 - val;
    }
    csum = csum << ((8 - ((ctx.params.len2 * ctx.params.lg_w) % 8)) % 8);

    let len2_bytes = (ctx.params.len2 * ctx.params.lg_w + 7) / 8;
    let csum_bytes = to_byte(csum, len2_bytes);
    let csum_base_w = base_2b(&csum_bytes, ctx.params.lg_w, ctx.params.len2);
    let full_msg = [msg_base_w, csum_base_w].concat();

    let n = ctx.params.n;
    let mut tmp = vec![0u8; ctx.params.len * n];
    for i in 0..ctx.params.len {
        adrs.set_chain_address(i as u32);
        let sig_block = &sig[i * n..(i + 1) * n];
        let val = chain(
            sig_block,
            full_msg[i],
            (ctx.params.w as u32) - 1 - full_msg[i],
            ctx,
            adrs,
        );
        tmp[i * n..(i + 1) * n].copy_from_slice(&val);
    }

    let mut wots_pk_adrs = *adrs;
    wots_pk_adrs.set_type_and_clear(WOTS_PK);
    wots_pk_adrs.set_key_pair_address(
        adrs.data[20..24]
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0),
    );

    // 15: pk_sig = T_len(PK.seed, wotspkADRS, tmp)
    hash_t_l(ctx, &wots_pk_adrs, &tmp)
}
