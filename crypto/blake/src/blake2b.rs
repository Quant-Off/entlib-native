//! BLAKE2b 코어 구현 모듈입니다.
//! RFC 7693 명세를 완전히 준수합니다.

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_base::error::hash::HashError;
use entlib_native_secure_buffer::SecureBuffer;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// BLAKE2b 상태 구조체입니다.
///
/// # Security Note
/// Drop 시 내부 체이닝 값과 카운터를 `write_volatile`로 강제 소거합니다.
pub struct Blake2b {
    h: [u64; 8],
    t: [u64; 2],
    buf: SecureBuffer,
    buf_len: usize,
    hash_len: usize,
}

impl Blake2b {
    /// 비키드(plain) BLAKE2b 인스턴스를 생성하는 함수입니다.
    ///
    /// # Errors
    /// `hash_len`이 1..=64 범위를 벗어나거나 SecureBuffer 할당 실패 시 패닉.
    pub fn new(hash_len: usize) -> Self {
        assert!((1..=64).contains(&hash_len), "hash_len must be 1..=64");
        Self::init(hash_len, 0)
    }

    /// 키드(keyed MAC) BLAKE2b 인스턴스를 생성하는 함수입니다.
    ///
    /// # Security Note
    /// 키는 128바이트 패딩 후 첫 번째 블록으로 처리됩니다.
    ///
    /// # Errors
    /// `key`가 1..=64 범위를 벗어나거나 `hash_len`이 범위를 벗어나면 패닉.
    pub fn new_keyed(hash_len: usize, key: &[u8]) -> Self {
        assert!((1..=64).contains(&hash_len), "hash_len must be 1..=64");
        assert!((1..=64).contains(&key.len()), "key len must be 1..=64");
        let mut state = Self::init(hash_len, key.len());
        // 키를 128바이트 블록으로 패딩하여 버퍼에 저장
        state.buf.as_mut_slice()[..key.len()].copy_from_slice(key);
        state.buf_len = 128;
        state
    }

    fn init(hash_len: usize, key_len: usize) -> Self {
        let p0 = (hash_len as u64)
            | ((key_len as u64) << 8)
            | (1u64 << 16) // fanout = 1
            | (1u64 << 24); // max_depth = 1
        let mut h = IV;
        h[0] ^= p0;
        Self {
            h,
            t: [0u64; 2],
            buf: SecureBuffer::new_owned(128).expect("Blake2b: SecureBuffer alloc failed"),
            buf_len: 0,
            hash_len,
        }
    }

    /// 데이터를 해시 상태에 공급하는 함수입니다.
    pub fn update(&mut self, data: &[u8]) {
        let mut input = data;
        loop {
            // 버퍼가 가득 차 있고 추가 데이터가 있을 때만 비-최종 압축
            if self.buf_len == 128 && !input.is_empty() {
                add_to_counter(&mut self.t, 128);
                let block = load_block(self.buf.as_slice());
                compress(&mut self.h, &block, self.t, [0u64, 0u64]);
                // 버퍼 소거 후 재사용
                for b in self.buf.as_mut_slice() {
                    *b = 0;
                }
                self.buf_len = 0;
            }
            if input.is_empty() {
                break;
            }
            let take = (128 - self.buf_len).min(input.len());
            self.buf.as_mut_slice()[self.buf_len..self.buf_len + take]
                .copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    /// 해시를 완료하고 다이제스트를 SecureBuffer로 반환하는 함수입니다.
    ///
    /// # Security Note
    /// 내부 상태는 함수 종료 시 Drop을 통해 소거됩니다.
    pub fn finalize(mut self) -> Result<SecureBuffer, HashError> {
        // 남은 바이트 수만큼 카운터 증가
        add_to_counter(&mut self.t, self.buf_len as u64);
        // 버퍼 나머지를 0으로 패딩
        for b in &mut self.buf.as_mut_slice()[self.buf_len..] {
            *b = 0;
        }
        let block = load_block(self.buf.as_slice());
        // 최종 블록: f[0] = 0xFFFF...
        compress(&mut self.h, &block, self.t, [0xFFFF_FFFF_FFFF_FFFF, 0u64]);

        let mut out = SecureBuffer::new_owned(self.hash_len)?;
        let out_slice = out.as_mut_slice();
        let mut pos = 0;
        for word in &self.h {
            let bytes = word.to_le_bytes();
            let take = (self.hash_len - pos).min(8);
            out_slice[pos..pos + take].copy_from_slice(&bytes[..take]);
            pos += take;
            if pos >= self.hash_len {
                break;
            }
        }
        Ok(out)
    }
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        for word in &mut self.h {
            unsafe { write_volatile(word, 0u64) };
        }
        unsafe {
            write_volatile(&mut self.t[0], 0u64);
            write_volatile(&mut self.t[1], 0u64);
            write_volatile(&mut self.buf_len, 0usize);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

//
// 내부 헬퍼
//

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], f: [u64; 2]) {
    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ t[0],
        IV[5] ^ t[1],
        IV[6] ^ f[0],
        IV[7] ^ f[1],
    ];
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn load_block(bytes: &[u8]) -> [u64; 16] {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let s = i * 8;
        *word = u64::from_le_bytes([
            bytes[s],
            bytes[s + 1],
            bytes[s + 2],
            bytes[s + 3],
            bytes[s + 4],
            bytes[s + 5],
            bytes[s + 6],
            bytes[s + 7],
        ]);
    }
    m
}

fn add_to_counter(t: &mut [u64; 2], n: u64) {
    let (new_t0, overflow) = t[0].overflowing_add(n);
    t[0] = new_t0;
    if overflow {
        t[1] = t[1].wrapping_add(1);
    }
}
