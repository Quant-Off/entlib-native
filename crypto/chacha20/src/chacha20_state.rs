use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_constant_time::constant_time::ConstantTimeOps;
use entlib_native_core_secure::secure_buffer::SecureBuffer;

/// 내부 연산을 위해 캡슐화된 ChaCha20 상태(state) 구조체입니다.
/// 메모리 안전성을 위해 스코프를 벗어날 때 즉각적으로 데이터를 소거(zeroize)합니다.
struct ChaCha20State {
    inner: [u32; 16],
}

impl ChaCha20State {
    #[inline(always)]
    fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];

        // 상수(constants) "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // 키(key)
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // 카운터(counter)
        state[12] = counter;

        // 논스(nonce)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(nonce[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        Self { inner: state }
    }

    #[inline(always)]
    fn process_block(&mut self, output: &mut [u8; 64]) {
        let mut working_state = self.inner;

        for _ in 0..10 {
            // 열 라운드(column round)
            self.quarter_round_on_state(&mut working_state, 0, 4, 8, 12);
            self.quarter_round_on_state(&mut working_state, 1, 5, 9, 13);
            self.quarter_round_on_state(&mut working_state, 2, 6, 10, 14);
            self.quarter_round_on_state(&mut working_state, 3, 7, 11, 15);

            // 대각선 라운드(diagonal round)
            self.quarter_round_on_state(&mut working_state, 0, 5, 10, 15);
            self.quarter_round_on_state(&mut working_state, 1, 6, 11, 12);
            self.quarter_round_on_state(&mut working_state, 2, 7, 8, 13);
            self.quarter_round_on_state(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.inner[i]);
            let bytes = working_state[i].to_le_bytes();
            output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        // 블록 처리 완료 후 워킹 상태 명시적 소거(zeroize)
        for word in working_state.iter_mut() {
            unsafe {
                write_volatile(word, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[inline(always)]
    fn quarter_round_on_state(
        &self,
        state: &mut [u32; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    ) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    #[inline(always)]
    fn increment_counter(&mut self) {
        self.inner[12] = self.inner[12].wrapping_add(1);
    }
}

impl Drop for ChaCha20State {
    fn drop(&mut self) {
        for word in self.inner.iter_mut() {
            unsafe {
                write_volatile(word, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// ChaCha20 알고리즘을 사용하여 데이터를 암호화 또는 복호화합니다.
/// 연산 결과는 자바(java) 힙의 생명주기와 분리된 `SecureBuffer`로 반환됩니다.
pub fn process_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    initial_counter: u32,
    data: &[u8],
) -> SecureBuffer {
    let mut state = ChaCha20State::new(key, nonce, initial_counter);
    let mut result = SecureBuffer {
        inner: vec![0u8; data.len()],
    };

    let mut key_stream_block = [0u8; 64];
    let mut chunks = data.chunks_exact(64);
    let mut out_chunks = result.inner.chunks_exact_mut(64);

    // 전체 블록(full block) 처리
    for (chunk, out_chunk) in chunks.by_ref().zip(out_chunks.by_ref()) {
        state.process_block(&mut key_stream_block);
        for i in 0..64 {
            out_chunk[i] = chunk[i] ^ key_stream_block[i];
        }
        state.increment_counter();
    }

    // 잔여 블록(partial block) 처리
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let out_remainder = out_chunks.into_remainder();
        let rem_len = remainder.len();
        state.process_block(&mut key_stream_block);

        // 메모리 경계(out-of-bounds) 오류를 방지하기 위해 64바이트 임시 버퍼 사용
        let mut temp_block = [0u8; 64];

        temp_block[..rem_len].copy_from_slice(&remainder[..rem_len]);

        // 전체 블록 길이에 대해 고정 반복하여 암호화 핵심 연산의 타이밍 리스크 제거
        for i in 0..64 {
            let xored = temp_block[i] ^ key_stream_block[i];

            // 인덱스 `i`가 잔여 블록 길이(`rem_len`) 미만인지 판별하는 상수-시간 마스크(mask) 생성
            // `i - rem_len`이 음수이면 참(All 1s), 0 이상이면 거짓(0) 반환
            let diff = (i as isize).wrapping_sub(rem_len as isize);
            let mask = diff.ct_is_negative() as u8;

            // 마스크에 따라 XOR된 값 또는 원본 임시 버퍼 값 선택 (CT MUX)
            temp_block[i] = xored.ct_select(temp_block[i], mask);
        }

        // 마스킹이 완료된 안전한 데이터를 결과 버퍼에 복사
        out_remainder[..rem_len].copy_from_slice(&temp_block[..rem_len]);

        // 임시 버퍼 안전 소거(zeroize)
        for byte in temp_block.iter_mut() {
            unsafe {
                write_volatile(byte, 0);
            }
        }
    }

    // 키 스트림 블록 안전 소거
    for byte in key_stream_block.iter_mut() {
        unsafe {
            write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    result
}
