//! NIST SP 800-56C Rev. 2 HKDF 구현

use entlib_native_core_secure::secure_buffer::SecureBuffer;
use std::cmp::min;

/// KDF에 사용할 해시 함수의 범용 트레이트
pub trait HkdfHash {
    const BLOCK_SIZE: usize;
    const OUTPUT_SIZE: usize;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>;
}

pub(crate) struct HmacKeyPads {
    pub i_pad: Vec<u8>,
    pub o_pad: Vec<u8>,
}

impl Drop for HmacKeyPads {
    fn drop(&mut self) {
        // 메모리 안전 소거
        for b in self.i_pad.iter_mut() {
            *b = 0;
        }
        for b in self.o_pad.iter_mut() {
            *b = 0;
        }
    }
}

pub(crate) fn precompute_hmac_pads<H: HkdfHash>(key: &[u8]) -> HmacKeyPads {
    let mut normalized_key = vec![0u8; H::BLOCK_SIZE];

    if key.len() > H::BLOCK_SIZE {
        let mut h = H::new();
        h.update(key);
        let hash = h.finalize();
        normalized_key[..hash.len()].copy_from_slice(&hash);
        let _cleanup = SecureBuffer { inner: hash };
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = vec![0u8; H::BLOCK_SIZE];
    let mut o_pad = vec![0u8; H::BLOCK_SIZE];

    for i in 0..H::BLOCK_SIZE {
        i_pad[i] = normalized_key[i] ^ 0x36;
        o_pad[i] = normalized_key[i] ^ 0x5c;
    }

    let _cleanup_key = SecureBuffer {
        inner: normalized_key,
    };
    HmacKeyPads { i_pad, o_pad }
}

/// SP 800-56C Rev. 2 Step 1: Randomness Extraction
/// K_mc = HMAC-Hash(salt, Z)
pub(crate) fn sp800_56c_extract<H: HkdfHash>(salt: Option<&[u8]>, z: &[u8]) -> SecureBuffer {
    // Q. T. Felix NOTE: 주의: SP 800-56C Rev 2는 Salt가 없을 경우 Hash의 'Block Size'만큼의 0 배열을 강제함
    let zero_salt = vec![0u8; H::BLOCK_SIZE];
    let actual_salt = salt.unwrap_or(&zero_salt);

    let pads = precompute_hmac_pads::<H>(actual_salt);

    let mut h_inner = H::new();
    h_inner.update(&pads.i_pad);
    h_inner.update(z); // Z is the shared secret (IKM)
    let inner_res = h_inner.finalize();

    let mut h_outer = H::new();
    h_outer.update(&pads.o_pad);
    h_outer.update(&inner_res);
    let k_mc = h_outer.finalize();

    let _c1 = SecureBuffer { inner: inner_res };
    SecureBuffer { inner: k_mc }
}

/// SP 800-56C Rev. 2 Step 2: Key Expansion (Using SP 800-108 Counter Mode)
/// K(i) = HMAC-Hash(K_mc, [i]_2 || Label || 0x00 || Context || [L]_2)
pub(crate) fn sp800_56c_expand_counter_mode<H: HkdfHash>(
    k_mc: &[u8],
    label: &[u8],
    context: &[u8],
    len_bytes: usize,
) -> Result<SecureBuffer, &'static str> {
    let l_bits = (len_bytes as u64) * 8;

    // 32비트 카운터 및 L 길이 한계 검증
    if l_bits == 0 || len_bytes > (u32::MAX as usize) * H::OUTPUT_SIZE {
        return Err("SP 800-108 Expand: Requested length invalid or too large");
    }

    let pads = precompute_hmac_pads::<H>(k_mc);
    let mut okm = Vec::with_capacity(len_bytes);

    let n = (len_bytes + H::OUTPUT_SIZE - 1) / H::OUTPUT_SIZE;
    let l_bits_bytes = (l_bits as u32).to_be_bytes(); // [L]_2 (32-bit Big Endian)

    for i in 1..=n {
        let i_bytes = (i as u32).to_be_bytes(); // [i]_2 (32-bit Big Endian)

        let mut h_in = H::new();
        h_in.update(&pads.i_pad);

        // SP 800-108 Counter Mode Data Encoding
        h_in.update(&i_bytes); // 1. [i]_2
        h_in.update(label); // 2. Label
        h_in.update(&[0x00]); // 3. 0x00 Separator
        h_in.update(context); // 4. Context
        h_in.update(&l_bits_bytes); // 5. [L]_2

        let inner_hash = h_in.finalize();

        let mut h_out = H::new();
        h_out.update(&pads.o_pad);
        h_out.update(&inner_hash);
        let t_block = h_out.finalize();

        let remaining = len_bytes - okm.len();
        let copy_len = min(t_block.len(), remaining);
        okm.extend_from_slice(&t_block[..copy_len]);

        let _c1 = SecureBuffer { inner: inner_hash };
        let _c2 = SecureBuffer { inner: t_block }; // 블록 데이터 임시 소거
    }

    Ok(SecureBuffer { inner: okm })
}
