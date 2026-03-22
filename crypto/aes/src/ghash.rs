//! GHASH 인증 함수 모듈입니다.
//! NIST SP 800-38D 준거 GF(2^128) 상수-시간 연산으로 GCM 인증 태그를 계산합니다.

use core::ptr::write_volatile;

// GCM GF(2^128) 곱셈: 환원 다항식 x^128 + x^7 + x^2 + x + 1
// R = 0xE100...00 (128비트, MSB 우선)
// 128회 고정 반복 — 분기 없음, 상수-시간 보장
#[inline(never)]
fn gf128_mul(x: &mut [u64; 2], h: &[u64; 2]) {
    let mut z = [0u64; 2];
    let mut v = *h;

    for i in 0u32..128 {
        let word = (i >> 6) as usize;
        let bit = 63 - (i & 63);

        // x의 i번째 비트 (MSB 우선) 추출 — 마스크 트릭, 분기 없음
        let xi = ((x[word] >> bit) & 1).wrapping_neg();
        z[0] ^= v[0] & xi;
        z[1] ^= v[1] & xi;

        // v를 오른쪽으로 1비트 시프트
        let lsb = v[1] & 1;
        v[1] = (v[1] >> 1) | (v[0] << 63);
        v[0] >>= 1;

        // LSB가 1이면 R로 XOR 환원 — 분기 없음
        let r_mask = lsb.wrapping_neg();
        v[0] ^= 0xE100000000000000u64 & r_mask;
    }

    *x = z;
}

/// GCM 인증 태그 계산을 위한 GHASH 상태 구조체입니다.
/// `Drop` 시 내부 H 값과 누산 상태를 소거합니다.
pub struct GHashState {
    h: [u64; 2],
    state: [u64; 2],
}

impl GHashState {
    /// GHASH 상태를 초기화하는 함수입니다.
    ///
    /// # Arguments
    /// `h_block` — H = AES_K(0^128) 블록
    pub fn new(h_block: &[u8; 16]) -> Self {
        let h = [
            u64::from_be_bytes([
                h_block[0], h_block[1], h_block[2], h_block[3], h_block[4], h_block[5], h_block[6],
                h_block[7],
            ]),
            u64::from_be_bytes([
                h_block[8],
                h_block[9],
                h_block[10],
                h_block[11],
                h_block[12],
                h_block[13],
                h_block[14],
                h_block[15],
            ]),
        ];
        Self {
            h,
            state: [0u64; 2],
        }
    }

    fn update_block(&mut self, block: &[u8; 16]) {
        let b0 = u64::from_be_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let b1 = u64::from_be_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);
        self.state[0] ^= b0;
        self.state[1] ^= b1;
        gf128_mul(&mut self.state, &self.h);
    }

    /// 데이터를 GHASH 상태에 누적하는 함수입니다. 16바이트 단위로 처리하며 나머지는 0 패딩합니다.
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i + 16 <= data.len() {
            let block: [u8; 16] = [
                data[i],
                data[i + 1],
                data[i + 2],
                data[i + 3],
                data[i + 4],
                data[i + 5],
                data[i + 6],
                data[i + 7],
                data[i + 8],
                data[i + 9],
                data[i + 10],
                data[i + 11],
                data[i + 12],
                data[i + 13],
                data[i + 14],
                data[i + 15],
            ];
            self.update_block(&block);
            i += 16;
        }
        let rem = data.len() - i;
        if rem > 0 {
            let mut buf = [0u8; 16];
            buf[..rem].copy_from_slice(&data[i..]);
            self.update_block(&buf);
            for b in &mut buf {
                unsafe { write_volatile(b, 0) };
            }
        }
    }

    /// GHASH 최종값을 반환하는 함수입니다.
    /// AAD/암호문 길이 블록을 처리한 뒤 16바이트 GHASH 출력을 반환합니다.
    ///
    /// # Arguments
    /// - `aad_len` — AAD 바이트 수
    /// - `ct_len` — 암호문 바이트 수
    pub fn finalize(mut self, aad_len: u64, ct_len: u64) -> [u8; 16] {
        let aad_bits = aad_len * 8;
        let ct_bits = ct_len * 8;
        let mut len_block = [0u8; 16];
        len_block[0] = (aad_bits >> 56) as u8;
        len_block[1] = (aad_bits >> 48) as u8;
        len_block[2] = (aad_bits >> 40) as u8;
        len_block[3] = (aad_bits >> 32) as u8;
        len_block[4] = (aad_bits >> 24) as u8;
        len_block[5] = (aad_bits >> 16) as u8;
        len_block[6] = (aad_bits >> 8) as u8;
        len_block[7] = aad_bits as u8;
        len_block[8] = (ct_bits >> 56) as u8;
        len_block[9] = (ct_bits >> 48) as u8;
        len_block[10] = (ct_bits >> 40) as u8;
        len_block[11] = (ct_bits >> 32) as u8;
        len_block[12] = (ct_bits >> 24) as u8;
        len_block[13] = (ct_bits >> 16) as u8;
        len_block[14] = (ct_bits >> 8) as u8;
        len_block[15] = ct_bits as u8;
        self.update_block(&len_block);

        let s = self.state;
        let mut out = [0u8; 16];
        let hi = s[0].to_be_bytes();
        let lo = s[1].to_be_bytes();
        out[..8].copy_from_slice(&hi);
        out[8..].copy_from_slice(&lo);
        out
    }
}

impl Drop for GHashState {
    fn drop(&mut self) {
        for w in &mut self.state {
            unsafe { write_volatile(w, 0) };
        }
        for w in &mut self.h {
            unsafe { write_volatile(w, 0) };
        }
    }
}
