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

// Table 2. SLH-DSA parameter sets
// FIPS 205의 정의에 따라 기본 파라미터 및 유도된 파라미터를 모두 포함하는 구조체

/// 해시 함수 타입 (SHAKE vs SHA2)
/// FIPS 205 명세에 따라 SLH-DSA 알고리즘이 가질 수 있는 해시 유형을 정의
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Shake,
    Sha2, // 보안 카테고리: 1, 3, 5
}

#[derive(Debug, Clone, Copy)]
pub struct SLHDSAParams {
    // Identification
    pub name: &'static str,
    pub hash_type: HashType,

    // Primary parameters
    pub n: usize,       // Security parameter (bytes)
    pub h: usize,       // Hypertree height
    pub d: usize,       // Hypertree layers
    pub h_prime: usize, // h / d (XMSS tree height)
    pub a: usize,       // FORS tree height
    pub k: usize,       // Number of FORS trees
    pub lg_w: usize,    // Winternitz parameter (usually 4)
    pub m: usize,       // Message digest length (bytes)

    // Derived parameters
    pub w: usize,         // 2^lg_w
    pub len1: usize,      // ceil(8n / lg_w)
    pub len2: usize,      // floor(log2(len1 * (w-1)) / lg_w) + 1
    pub len: usize,       // len1 + len2
    pub bytes_pk: usize,  // 2 * n
    pub bytes_sig: usize, // (1 + k(1+a) + h + d*len) * n
}

//
// Parameter Set - start
//

pub const SHA2_128S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-128s",
    hash_type: HashType::Sha2,
    n: 16,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 12,
    k: 14,
    lg_w: 4,
    m: 30,
    w: 16,
    len1: 32,
    len2: 3,
    len: 35,
    bytes_pk: 32,
    bytes_sig: 7856,
};

pub const SHA2_128F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-128f",
    hash_type: HashType::Sha2,
    n: 16,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 6,
    k: 33,
    lg_w: 4,
    m: 34,
    w: 16,
    len1: 32,
    len2: 3,
    len: 35,
    bytes_pk: 32,
    bytes_sig: 17088,
};

pub const SHA2_192S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-192s",
    hash_type: HashType::Sha2,
    n: 24,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 14,
    k: 17,
    lg_w: 4,
    m: 39,
    w: 16,
    len1: 48,
    len2: 3,
    len: 51,
    bytes_pk: 48,
    bytes_sig: 16224,
};

pub const SHA2_192F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-192f",
    hash_type: HashType::Sha2,
    n: 24,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 8,
    k: 33,
    lg_w: 4,
    m: 42,
    w: 16,
    len1: 48,
    len2: 3,
    len: 51,
    bytes_pk: 48,
    bytes_sig: 35664,
};

pub const SHA2_256S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-256s",
    hash_type: HashType::Sha2,
    n: 32,
    h: 64,
    d: 8,
    h_prime: 8,
    a: 14,
    k: 22,
    lg_w: 4,
    m: 47,
    w: 16,
    len1: 64,
    len2: 3,
    len: 67,
    bytes_pk: 64,
    bytes_sig: 29792,
};

pub const SHA2_256F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHA2-256f",
    hash_type: HashType::Sha2,
    n: 32,
    h: 68,
    d: 17,
    h_prime: 4,
    a: 9,
    k: 35,
    lg_w: 4,
    m: 49,
    w: 16,
    len1: 64,
    len2: 3,
    len: 67,
    bytes_pk: 64,
    bytes_sig: 49856,
};

pub const SHAKE_128S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-128s",
    hash_type: HashType::Shake,
    n: 16,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 12,
    k: 14,
    lg_w: 4,
    m: 30,
    w: 16,
    len1: 32,
    len2: 3,
    len: 35,
    bytes_pk: 32,
    bytes_sig: 7856,
};

pub const SHAKE_128F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-128f",
    hash_type: HashType::Shake,
    n: 16,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 6,
    k: 33,
    lg_w: 4,
    m: 34,
    w: 16,
    len1: 32,
    len2: 3,
    len: 35,
    bytes_pk: 32,
    bytes_sig: 17088,
};

pub const SHAKE_192S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-192s",
    hash_type: HashType::Shake,
    n: 24,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 14,
    k: 17,
    lg_w: 4,
    m: 39,
    w: 16,
    len1: 48,
    len2: 3,
    len: 51,
    bytes_pk: 48,
    bytes_sig: 16224,
};

pub const SHAKE_192F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-192f",
    hash_type: HashType::Shake,
    n: 24,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 8,
    k: 33,
    lg_w: 4,
    m: 42,
    w: 16,
    len1: 48,
    len2: 3,
    len: 51,
    bytes_pk: 48,
    bytes_sig: 35664,
};

pub const SHAKE_256S: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-256s",
    hash_type: HashType::Shake,
    n: 32,
    h: 64,
    d: 8,
    h_prime: 8,
    a: 14,
    k: 22,
    lg_w: 4,
    m: 47,
    w: 16,
    len1: 64,
    len2: 3,
    len: 67,
    bytes_pk: 64,
    bytes_sig: 29792,
};

pub const SHAKE_256F: SLHDSAParams = SLHDSAParams {
    name: "SLH-DSA-SHAKE-256f",
    hash_type: HashType::Shake,
    n: 32,
    h: 68,
    d: 17,
    h_prime: 4,
    a: 9,
    k: 35,
    lg_w: 4,
    m: 49,
    w: 16,
    len1: 64,
    len2: 3,
    len: 67,
    bytes_pk: 64,
    bytes_sig: 49856,
};

//
// Parameter Set - end
//

/// 이름으로 파라미터 불러오는거
pub fn get_params_by_name(name: &str) -> Option<SLHDSAParams> {
    match name {
        "SLH-DSA-SHA2-128s" => Some(SHA2_128S),
        "SLH-DSA-SHAKE-128s" => Some(SHAKE_128S),
        "SLH-DSA-SHA2-128f" => Some(SHA2_128F),
        "SLH-DSA-SHAKE-128f" => Some(SHAKE_128F),
        "SLH-DSA-SHA2-192s" => Some(SHA2_192S),
        "SLH-DSA-SHAKE-192s" => Some(SHAKE_192S),
        "SLH-DSA-SHA2-192f" => Some(SHA2_192F),
        "SLH-DSA-SHAKE-192f" => Some(SHAKE_192F),
        "SLH-DSA-SHA2-256s" => Some(SHA2_256S),
        "SLH-DSA-SHAKE-256s" => Some(SHAKE_256S),
        "SLH-DSA-SHA2-256f" => Some(SHA2_256F),
        "SLH-DSA-SHAKE-256f" => Some(SHAKE_256F),
        _ => None,
    }
}

// 유틸
// Integer to Big-Endian Bytes [cite: 2271]
pub fn to_byte(in_val: u32, out_len: usize) -> Vec<u8> {
    let mut res = vec![0u8; out_len];
    for i in 0..out_len {
        res[out_len - 1 - i] = (in_val >> (8 * i)) as u8;
    }
    res
}
