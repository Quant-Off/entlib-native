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
    ///
    /// # Arguments
    /// - last_byte_bits 마지막 바이트의 유효 비트 수 (0~7). 0인 경우 8비트(전체)가 유효하거나 바이트 정렬됨을 의미
    fn pad(&mut self, last_byte_opt: Option<(u8, usize)>) {
        let mut valid_bits = 0;

        if let Some((last_byte, bits)) = last_byte_opt {
            valid_bits = bits;
            let mask = (1u8 << valid_bits) - 1;
            self.buffer[self.buffer_len] = last_byte & mask;
        } else {
            self.buffer[self.buffer_len] = 0;
        }

        // 도메인 구분자와 패딩 시작 비트(1) 병합
        let padding = (self.domain as u16) << valid_bits;
        self.buffer[self.buffer_len] |= (padding & 0xFF) as u8;
        self.buffer_len += 1;

        // 패딩이 바이트 경계를 넘어가는 경우 (오버플로)
        if padding > 0xFF {
            if self.buffer_len == self.rate_bytes {
                self.process_buffer();
                self.buffer_len = 0;
            }
            self.buffer[self.buffer_len] = (padding >> 8) as u8;
            self.buffer_len += 1;
        }

        // Q. T. Felix NOTE: Keccak 10*1 패딩 비트 충돌(Collision) 감지 추가
        //                   블록이 정확히 가득 찼는데(rate_bytes) 방금 추가한 도메인/시작 패딩이
        //                   블록의 마지막 비트(0x80)를 점유했다면 즉시 압축하고 새 블록을 생성해야 함
        if self.buffer_len == self.rate_bytes && (self.buffer[self.rate_bytes - 1] & 0x80) != 0 {
            self.process_buffer();
            self.buffer_len = 0;
        }

        // 남은 공간 0으로 채움
        self.buffer[self.buffer_len..self.rate_bytes].fill(0);

        // 스펀지 구조의 최종 종료 패딩 비트(0x80) 설정
        self.buffer[self.rate_bytes - 1] |= 0x80;

        self.process_buffer();
    }

    /// 해시 연산 종료 및 다이제스트(digest) 반환
    ///
    /// # Arguments
    /// - last_byte_bits 마지막 바이트의 유효 비트 수 (0 = 바이트 정렬)
    pub(crate) fn finalize(mut self, output_len: usize, last_byte_opt: Option<(u8, usize)>) -> Vec<u8> {
        self.pad(last_byte_opt);

        let mut out = Vec::with_capacity(output_len);
        while out.len() < output_len {
            for i in 0..(self.rate_bytes / 8) {
                if out.len() >= output_len {
                    break;
                }
                let word_bytes = self.state[i].to_le_bytes();
                let take = core::cmp::min(8, output_len - out.len());
                out.extend_from_slice(&word_bytes[..take]);
            }
            if out.len() < output_len {
                Self::keccak_f1600(&mut self.state);
            }
        }
        out
    }
}
