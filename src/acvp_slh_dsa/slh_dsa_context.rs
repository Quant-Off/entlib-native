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
use crate::acvp_slh_dsa::slh_dsa_params::{HashType, SLHDSAParams};
use sha2::{Sha256, Sha512};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone)]
pub struct SlhContext {
    pub(crate) pk_seed: Vec<u8>,
    pub(crate) sk_seed: Vec<u8>,
    pub(crate) pk_root: Vec<u8>,
    pub(crate) params: SLHDSAParams,
}

impl SlhContext {
    pub fn new(params: SLHDSAParams, pk_seed: Vec<u8>, sk_seed: Vec<u8>, pk_root: Vec<u8>) -> Self {
        Self {
            pk_seed,
            sk_seed,
            pk_root,
            params,
        }
    }

    /// ADRS SHA2로 압축(22 bytes): FIPS 205 Section 11.2 [cite: 3297]
    fn compress_adrs(&self, adrs: &Adrs) -> Vec<u8> {
        let mut result = Vec::with_capacity(22);
        // Offset 0: layer (1 byte from position 3)
        result.push(adrs.data[3]);
        // Offset 1-8: tree (8 bytes from positions 4-11)
        result.extend_from_slice(&adrs.data[4..12]);
        // Offset 9: type (1 byte from position 19)
        result.push(adrs.data[19]);
        // Offset 10-21: type-specific (12 bytes from positions 20-31)
        result.extend_from_slice(&adrs.data[20..32]);
        result
    }

    /// SHA-256 헬퍼
    fn sha256_hash(&self, inputs: &[&[u8]]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        for input in inputs {
            Digest::update(&mut hasher, input);
        }
        hasher.finalize().into()
    }

    /// SHA-512 헬퍼
    fn sha512_hash(&self, inputs: &[&[u8]]) -> [u8; 64] {
        use sha2::Digest;
        let mut hasher = Sha512::new();
        for input in inputs {
            Digest::update(&mut hasher, input);
        }
        hasher.finalize().into()
    }

    /// MGF1-SHA-256 mask generation function
    fn mgf1_sha256(&self, seed: &[u8], mask_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(mask_len);
        let mut counter: u32 = 0;
        while output.len() < mask_len {
            let hash = self.sha256_hash(&[seed, &counter.to_be_bytes()]);
            output.extend_from_slice(&hash);
            counter += 1;
        }
        output.truncate(mask_len);
        output
    }

    /// MGF1-SHA-512 mask generation function
    fn mgf1_sha512(&self, seed: &[u8], mask_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(mask_len);
        let mut counter: u32 = 0;
        while output.len() < mask_len {
            let hash = self.sha512_hash(&[seed, &counter.to_be_bytes()]);
            output.extend_from_slice(&hash);
            counter += 1;
        }
        output.truncate(mask_len);
        output
    }

    // ... (PRF_addr, PRF_msg, F are correct in previous code, include them here) ...
    // PRF_addr: Always SHA-256 for SHA2 variants [cite: 3323, 3338]
    // PRF_msg: HMAC-SHA-256 (n=16) or HMAC-SHA-512 (n>16) [cite: 3325, 3340]
    // F: Always SHA-256 for SHA2 variants [cite: 3327, 3342]

    pub fn prf_addr(&self, adrs: &Adrs) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.prf_addr_shake(adrs),
            HashType::Sha2 => self.prf_addr_sha2(adrs),
        }
    }

    fn prf_addr_shake(&self, adrs: &Adrs) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(&self.pk_seed);
        hasher.update(&adrs.data);
        hasher.update(&self.sk_seed);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; self.params.n];
        reader.read(&mut out);
        out
    }

    fn prf_addr_sha2(&self, adrs: &Adrs) -> Vec<u8> {
        let n = self.params.n;
        let adrs_c = self.compress_adrs(adrs);
        let padding = vec![0u8; 64 - n];
        let result = self.sha256_hash(&[&self.pk_seed, &padding, &adrs_c, &self.sk_seed]);
        result[..n].to_vec()
    }

    pub fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.prf_msg_shake(sk_prf, opt_rand, msg),
            HashType::Sha2 => self.prf_msg_sha2(sk_prf, opt_rand, msg),
        }
    }

    fn prf_msg_shake(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(sk_prf);
        hasher.update(opt_rand);
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; self.params.n];
        reader.read(&mut out);
        out
    }

    fn prf_msg_sha2(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
        let n = self.params.n;
        let block_size = if n == 16 { 64 } else { 128 };
        let ipad = vec![0x36; block_size];
        let opad = vec![0x5c; block_size];
        let mut key = sk_prf.to_vec();
        key.resize(block_size, 0);
        let k_ipad: Vec<u8> = key.iter().zip(ipad.iter()).map(|(k, p)| k ^ p).collect();
        let k_opad: Vec<u8> = key.iter().zip(opad.iter()).map(|(k, p)| k ^ p).collect();

        if n == 16 {
            let inner_hash = self.sha256_hash(&[&k_ipad, opt_rand, msg]);
            let result = self.sha256_hash(&[&k_opad, &inner_hash]);
            result[..n].to_vec()
        } else {
            let inner_hash = self.sha512_hash(&[&k_ipad, opt_rand, msg]);
            let result = self.sha512_hash(&[&k_opad, &inner_hash]);
            result[..n].to_vec()
        }
    }

    pub fn f(&self, adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.f_shake(adrs, m1),
            HashType::Sha2 => self.f_sha2(adrs, m1),
        }
    }

    fn f_shake(&self, adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(&self.pk_seed);
        hasher.update(&adrs.data);
        hasher.update(m1);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; self.params.n];
        reader.read(&mut out);
        out
    }

    fn f_sha2(&self, adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
        let n = self.params.n;
        let adrs_c = self.compress_adrs(adrs);
        let padding = vec![0u8; 64 - n];
        let result = self.sha256_hash(&[&self.pk_seed, &padding, &adrs_c, m1]);
        result[..n].to_vec()
    }

    // =========================================================================
    // H(PK.seed, ADRS, M2)
    // =========================================================================
    pub fn h(&self, adrs: &Adrs, m2: &[u8]) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.h_shake(adrs, m2),
            HashType::Sha2 => self.h_sha2(adrs, m2),
        }
    }

    fn h_shake(&self, adrs: &Adrs, m2: &[u8]) -> Vec<u8> {
        self.f_shake(adrs, m2)
    }

    /// SHA2: H(PK.seed, ADRS, M2)
    /// [cite: 3344] For Category 3 & 5 (n > 16), use SHA-512.
    fn h_sha2(&self, adrs: &Adrs, m2: &[u8]) -> Vec<u8> {
        let n = self.params.n;
        let adrs_c = self.compress_adrs(adrs);

        if n == 16 {
            // Security Category 1: Trunc(SHA-256(...)) [cite: 3329]
            let padding = vec![0u8; 64 - n];
            let result = self.sha256_hash(&[&self.pk_seed, &padding, &adrs_c, m2]);
            result[..n].to_vec()
        } else {
            // Security Category 3, 5: Trunc(SHA-512(...)) [cite: 3344]
            let padding = vec![0u8; 128 - n];
            let result = self.sha512_hash(&[&self.pk_seed, &padding, &adrs_c, m2]);
            result[..n].to_vec()
        }
    }

    // =========================================================================
    // T_l(PK.seed, ADRS, M)
    // =========================================================================
    pub fn t_l(&self, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.t_l_shake(adrs, m),
            HashType::Sha2 => self.t_l_sha2(adrs, m),
        }
    }

    fn t_l_shake(&self, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(&self.pk_seed);
        hasher.update(&adrs.data);
        hasher.update(m);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; self.params.n];
        reader.read(&mut out);
        out
    }

    /// SHA2: T_l(PK.seed, ADRS, M)
    /// [cite: 3346] For Category 3 & 5 (n > 16), use SHA-512.
    fn t_l_sha2(&self, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
        let n = self.params.n;
        let adrs_c = self.compress_adrs(adrs);

        if n == 16 {
            // Security Category 1: Trunc(SHA-256(...)) [cite: 3331]
            let padding = vec![0u8; 64 - n];
            let hash = self.sha256_hash(&[&self.pk_seed, &padding, &adrs_c, m]);
            hash[..n].to_vec()
        } else {
            // Security Category 3, 5: Trunc(SHA-512(...)) [cite: 3346]
            let padding = vec![0u8; 128 - n];
            let hash = self.sha512_hash(&[&self.pk_seed, &padding, &adrs_c, m]);
            hash[..n].to_vec()
        }
    }

    // =========================================================================
    // H_msg(R, PK.seed, PK.root, M)
    // =========================================================================
    pub fn h_msg(&self, r: &[u8], msg: &[u8]) -> Vec<u8> {
        match self.params.hash_type {
            HashType::Shake => self.h_msg_shake(r, msg),
            HashType::Sha2 => self.h_msg_sha2(r, msg),
        }
    }

    fn h_msg_shake(&self, r: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(r);
        hasher.update(&self.pk_seed);
        hasher.update(&self.pk_root);
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; self.params.m];
        reader.read(&mut out);
        out
    }

    /// SHA2: H_msg
    /// FIPS 205 Section 11.2.2[cite: 3335]: MGF1-SHA-512(R || PK.seed || SHA-512(...), m)
    fn h_msg_sha2(&self, r: &[u8], msg: &[u8]) -> Vec<u8> {
        let n = self.params.n;
        let m = self.params.m;

        if n == 16 {
            // Inner: SHA-256(R || PK.seed || PK.root || M)
            let hash1 = self.sha256_hash(&[r, &self.pk_seed, &self.pk_root, msg]);

            // Outer: MGF1-SHA-256(R || PK.seed || hash1, m)
            // [Fix]: Prepend R || PK.seed to the seed for MGF1
            let mut mgf_seed = Vec::with_capacity(r.len() + self.pk_seed.len() + hash1.len());
            mgf_seed.extend_from_slice(r);
            mgf_seed.extend_from_slice(&self.pk_seed);
            mgf_seed.extend_from_slice(&hash1);

            self.mgf1_sha256(&mgf_seed, m)
        } else {
            // Inner: SHA-512(R || PK.seed || PK.root || M)
            let hash1 = self.sha512_hash(&[r, &self.pk_seed, &self.pk_root, msg]);

            // Outer: MGF1-SHA-512(R || PK.seed || hash1, m)
            // [Fix]: Prepend R || PK.seed to the seed for MGF1
            let mut mgf_seed = Vec::with_capacity(r.len() + self.pk_seed.len() + hash1.len());
            mgf_seed.extend_from_slice(r);
            mgf_seed.extend_from_slice(&self.pk_seed);
            mgf_seed.extend_from_slice(&hash1);

            self.mgf1_sha512(&mgf_seed, m)
        }
    }

    pub fn params(&self) -> &SLHDSAParams {
        &self.params
    }
}
