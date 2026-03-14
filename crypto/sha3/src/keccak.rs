use crate::KeccakState;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use entlib_native_secure_buffer::SecureBuffer;

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
            buffer: SecureBuffer::new_owned(200).expect("SecureBuffer allocate failed"),
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

    fn process_buffer(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks(8).enumerate() {
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
            let fill = self.rate_bytes - self.buffer_len;
            let remain = data.len() - offset;
            let is_ge = remain.ct_is_ge(&fill);
            let take = usize::ct_select(&fill, &remain, is_ge);

            self.buffer.as_mut_slice()[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[offset..offset + take]);
            self.buffer_len += take;
            offset += take;

            if self.buffer_len == self.rate_bytes {
                let mut temp_block = [0u8; 200]; // rete_bytes의 최대 크기 넉넉히 수용
                temp_block[..self.rate_bytes]
                    .copy_from_slice(&self.buffer.as_slice()[..self.rate_bytes]);
                self.process_buffer(&temp_block[..self.rate_bytes]);
                self.buffer_len = 0;
            }
        }
    }

    /// 메시지 패딩 및 최종 블록 처리
    ///
    /// # Arguments
    /// - last_byte_bits 마지막 바이트의 유효 비트 수 (0~7). 0인 경우 8비트(전체)가 유효하거나 바이트 정렬됨을 의미
    fn pad(&mut self, last_byte_opt: Option<(u8, usize)>) {
        // Q. T. Felix NOTE: Option은 컴파일러 최적화에 따라 분기를 유발할 수 있음.
        //                   나중에 (b: u8, bits: usize) 형태의 명시적 인자 전달 구조로 리팩토링.
        let (b, bits) = last_byte_opt.unwrap_or((0, 0));
        let valid_bits = bits;

        // 상수-시간 마스크로 불필요한 비트 제거 (오버플로 방지)
        let mask = ((1u16 << valid_bits).wrapping_sub(1)) as u8;
        let last_byte_val = b & mask;

        let padding = (self.domain as u16) << valid_bits;
        let p0 = (padding & 0xFF) as u8 | last_byte_val;
        let p1 = (padding >> 8) as u8;

        // padding > 0xFF (padding >= 0x0100)
        let has_p1 = padding.ct_is_ge(&0x0100u16);

        let rate = self.rate_bytes;
        let len = self.buffer_len;

        // Keccak 최대 rate_bytes 수용할 수 있는 고정 버퍼
        let mut block1 = [0u8; 200];
        let mut block2 = [0u8; 200];

        // 상수-시간 블럭 1,2 ㄹ데이터 구성
        let buf_slice = self.buffer.as_slice();
        let p1_to_block2 = len.ct_eq(&(rate - 1)) & has_p1;

        for i in 0..rate {
            // i < len
            let is_i_less_len = i.ct_is_ge(&len).choice_not();
            let is_i_eq_len = i.ct_eq(&len);
            let is_i_eq_len_plus_1 = i.ct_eq(&(len + 1));

            // i < len 이면 원래 버퍼, 아니면 0
            let mut byte = u8::ct_select(&buf_slice[i], &0, is_i_less_len);

            // i == len 위치에 p0 덮어쓰기
            byte = u8::ct_select(&p0, &byte, is_i_eq_len);

            // i == len + 1 이고 has_p1이 True인 위치에 p1 덮어쓰기
            let put_p1_here = is_i_eq_len_plus_1 & has_p1;
            byte = u8::ct_select(&p1, &byte, put_p1_here);

            block1[i] = byte;
        }

        // p1이 블럭 경계를 넘어간 경우 block2의 첫 번째 바이트에 저장
        block2[0] = u8::ct_select(&p1, &0, p1_to_block2);

        // 충동 및 추가 블럭 필요 여부 판별
        let len_after_pad = len + 1 + usize::ct_select(&1, &0, has_p1);

        // 패딩이 경계를 넘었는가?
        let spills_to_block2 = len_after_pad.ct_is_ge(&(rate + 1));
        // 블럭이 꽉 찼늗가?
        let exactly_full = len_after_pad.ct_eq(&rate);

        // 블럭이 가득 찼는데 마지막 바이트에 0x80 비트가 이미 존재하는지 상수-시간으로 검사 (keccak 10*1 충돌대응)
        let collision_bit = (block1[rate - 1] & 0x80).ct_eq(&0x80);
        let has_collision = exactly_full & collision_bit;

        // 추가 블럭(block2) 연산 결과를 최종 state에 반영해야 하는지 여부
        let needs_block2 = spills_to_block2 | has_collision;

        // 최종 스펀지 패딩 비트 상수-시간 배치
        // needs_block2가 True면 block2 끝에, 그렇지 않으면 block1 끝에 0x80 적용
        block1[rate - 1] =
            u8::ct_select(&block1[rate - 1], &(block1[rate - 1] | 0x80), needs_block2);
        block2[rate - 1] =
            u8::ct_select(&(block2[rate - 1] | 0x80), &block2[rate - 1], needs_block2);

        // 상수-시간 압축 수행
        // 첫 번째 블럭 처리 및 keccak 상태 백업
        self.process_buffer(&block1[..rate]);
        let state_after_block1 = self.state;

        // 두 번째 블럭 일괄 처리
        self.process_buffer(&block2[..rate]);

        // needs_block2가 False면 두 번째 블럭의 연산 결과를 폐기하고 첫 번째 결과로 상수-시간 롤백
        for (i, &saved) in state_after_block1.iter().enumerate() {
            self.state[i] = u64::ct_select(&self.state[i], &saved, needs_block2);
        }

        // 스택에 할당된 임시 패딩 데이터 완전 소거
        for b in &mut block1 {
            unsafe {
                write_volatile(b, 0);
            }
        }
        for b in &mut block2 {
            unsafe {
                write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);

        self.buffer_len = 0;
    }

    /// 해시 연산 종료 및 다이제스트(digest) 반환
    ///
    /// # Arguments
    /// - last_byte_bits 마지막 바이트의 유효 비트 수 (0 = 바이트 정렬)
    pub(crate) fn finalize(
        mut self,
        output_len: usize,
        last_byte_opt: Option<(u8, usize)>,
    ) -> Result<SecureBuffer, &'static str> {
        self.pad(last_byte_opt);

        let mut out_buf = SecureBuffer::new_owned(output_len)?;
        if output_len == 0 {
            return Ok(out_buf);
        }

        let out_slice = out_buf.as_mut_slice();
        let mut out_idx = 0;
        let rate_words = self.rate_bytes / 8;

        while out_idx < output_len {
            for i in 0..rate_words {
                // 출력 길이(output_len)는 스펙에 따른 공개 정보이라
                // 이를 기반으로 한 루프 탈출 분기문은 비밀 데이터의 타이밍을 누출하지 않음
                if out_idx >= output_len {
                    break;
                }
                let word_bytes = self.state[i].to_le_bytes();

                let remain = output_len - out_idx;
                let is_ge = remain.ct_is_ge(&8usize);
                let take = usize::ct_select(&8, &remain, is_ge);

                // 계산될 길이만큼 버퍼에 복사
                out_slice[out_idx..out_idx + take].copy_from_slice(&word_bytes[..take]);
                out_idx += take;
            }

            // 추가 출력이 필요하면 keccak 상태 갱신
            if out_idx < output_len {
                Self::keccak_f1600(&mut self.state);
            }
        }
        Ok(out_buf)
    }
}
