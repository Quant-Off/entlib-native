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
use crate::acvp_slh_dsa::slh_dsa_params::{SLHDSAParams, SHAKE_128F};
use rand::{rngs::OsRng, TryRngCore};
use crate::acvp_slh_dsa::xmss::xmss_node;

// Figure 16. SLH-DSA public key (dynamic size)
#[derive(Clone, Debug)]
pub struct SlhPublicKey {
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

impl SlhPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.pk_seed.len() + self.pk_root.len());
        out.extend_from_slice(&self.pk_seed);
        out.extend_from_slice(&self.pk_root);
        out
    }
}

// Figure 15. SLH-DSA private key (dynamic size)
#[derive(Clone)]
pub struct SlhPrivateKey {
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

impl SlhPrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.sk_seed.len() + self.sk_prf.len() + self.pk_seed.len() + self.pk_root.len()
        );
        out.extend_from_slice(&self.sk_seed);
        out.extend_from_slice(&self.sk_prf);
        out.extend_from_slice(&self.pk_seed);
        out.extend_from_slice(&self.pk_root);
        out
    }
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
/// ACVP 테스트 및 키 생성을 위한 내부 함수 (dynamic parameters)
pub fn slh_keygen_internal_with_params(
    params: SLHDSAParams,
    sk_seed: Vec<u8>,
    sk_prf: Vec<u8>,
    pk_seed: Vec<u8>
) -> (SlhPrivateKey, SlhPublicKey) {
    // 1: ADRS <- toByte(0, 32)
    let mut adrs = Adrs::new();

    // 2: ADRS.setLayerAddress(d - 1)
    adrs.set_layer_address((params.d - 1) as u32);

    // Tree Address를 명시적으로 0으로 설정
    adrs.set_tree_address(0);

    // Context preparation for xmss_node
    // KeyGen 시점에서는 PK.root가 아직 생성되지 않았으므로 빈 벡터를 사용합니다.
    let ctx = SlhContext::new(
        params,
        pk_seed.clone(),
        sk_seed.clone(),
        vec![0u8; params.n],
    );

    // 3: PK.root <- xmss_node(SK.seed, 0, h', PK.seed, ADRS)
    let pk_root = xmss_node(&ctx, 0, params.h_prime as u32, &mut adrs);

    // 4: return ((SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root))
    let sk = SlhPrivateKey {
        sk_seed,
        sk_prf,
        pk_seed: pk_seed.clone(),
        pk_root: pk_root.clone(),
    };

    let pk = SlhPublicKey {
        pk_seed,
        pk_root,
    };

    (sk, pk)
}

// Algorithm 21 slh_keygen() - uses default SHAKE_128F params
pub fn slh_keygen() -> Result<(SlhPrivateKey, SlhPublicKey), &'static str> {
    slh_keygen_with_params(SHAKE_128F)
}

// Algorithm 21 slh_keygen() with custom params
pub fn slh_keygen_with_params(params: SLHDSAParams) -> Result<(SlhPrivateKey, SlhPublicKey), &'static str> {
    let mut rng = OsRng;
    let n = params.n;

    let mut sk_seed = vec![0u8; n];
    let mut sk_prf = vec![0u8; n];
    let mut pk_seed = vec![0u8; n];

    // 1: SK.seed <- B^n
    let gen_sk_seed = rng.try_fill_bytes(&mut sk_seed);

    // 2: SK.prf <- B^n
    let gen_sk_prf = rng.try_fill_bytes(&mut sk_prf);

    // 3: PK.seed <- B^n
    let gen_pk_seed = rng.try_fill_bytes(&mut pk_seed);

    // 4-6: Check RNG failure
    if gen_sk_seed.is_err() || gen_sk_prf.is_err() || gen_pk_seed.is_err() {
        return Err("RNG generation failed");
    }

    // 7: return slh_keygen_internal(SK.seed, SK.prf, PK.seed)
    Ok(slh_keygen_internal_with_params(params, sk_seed, sk_prf, pk_seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_execution() {
        let result = slh_keygen();
        assert!(result.is_ok(), "Key generation failed");

        let (sk, pk) = result.unwrap();

        // Basic consistency check
        assert_eq!(sk.pk_seed, pk.pk_seed);
        assert_eq!(sk.pk_root, pk.pk_root);
        assert_eq!(sk.sk_seed.len(), SHAKE_128F.n);
    }
}
