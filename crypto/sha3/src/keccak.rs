use crate::KeccakState;
use core::cmp::min;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI_INDICES: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

impl KeccakState {
    pub(crate) fn new(rate_bits: usize, domain: u8) -> Self {
        Self {
            state: [0; 25],
            rate_bytes: rate_bits / 8,
            buffer: [0; 200],
            buffer_len: 0,
            domain,
        }
    }

    /// Keccak-f[1600] 순열(permutation) 함수
    fn keccak_f1600(state: &mut [u64; 25]) {
        let mut next_state = [0u64; 25];

        for rc in KECCAK_ROUND_CONSTANTS.iter() {
            // Theta
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for i in 0..25 {
                state[i] ^= d[i % 5];
            }

            // Rho & Pi
            for i in 0..25 {
                next_state[PI_INDICES[i]] = state[i].rotate_left(RHO_OFFSETS[i]);
            }

            // Chi
            for y in 0..5 {
                let y_offset = y * 5;
                for x in 0..5 {
                    state[y_offset + x] = next_state[y_offset + x]
                        ^ (!next_state[y_offset + ((x + 1) % 5)]
                            & next_state[y_offset + ((x + 2) % 5)]);
                }
            }

            // Iota
            state[0] ^= rc;
        }

        // 임시 상태의 메모리 안전한 소거(zeroization)
        for item in next_state.iter_mut() {
            unsafe {
                write_volatile(item, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// rate 바이트만큼 채워진 버퍼를 상태에 흡수(absorb)하고 순열 적용
    fn process_buffer(&mut self) {
        for (i, chunk) in self.buffer[..self.rate_bytes].chunks(8).enumerate() {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(chunk);
            self.state[i] ^= u64::from_le_bytes(word_bytes);
        }
        Self::keccak_f1600(&mut self.state);
    }

    /// 임의의 길이 데이터를 내부 버퍼에 누적 및 처리
    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let take = min(self.rate_bytes - self.buffer_len, data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[offset..offset + take]);
            self.buffer_len += take;
            offset += take;

            if self.buffer_len == self.rate_bytes {
                self.process_buffer();
                self.buffer_len = 0;
            }
        }
    }

    /// 메시지 패딩 및 최종 블록 처리
    fn pad(&mut self) {
        self.buffer[self.buffer_len] = self.domain;
        self.buffer[self.buffer_len + 1..self.rate_bytes].fill(0);
        self.buffer[self.rate_bytes - 1] |= 0x80;
        self.process_buffer();
    }

    /// 해시 연산 종료 및 다이제스트(digest) 반환
    pub(crate) fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.pad();

        let mut out = Vec::with_capacity(output_len);
        while out.len() < output_len {
            for i in 0..(self.rate_bytes / 8) {
                if out.len() >= output_len {
                    break;
                }
                let word_bytes = self.state[i].to_le_bytes();
                let take = min(8, output_len - out.len());
                out.extend_from_slice(&word_bytes[..take]);
            }
            if out.len() < output_len {
                Self::keccak_f1600(&mut self.state);
            }
        }

        // self가 범위를 벗어나면서 Drop 트레이트에 의해 내부 상태가 자동 소거됨
        out
    }
}
