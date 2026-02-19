use crate::Sha256State;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

const SHA_256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256State {
    pub(crate) fn new(is_224: bool) -> Self {
        let state = if is_224 {
            [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ]
        } else {
            [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ]
        };
        Self {
            state,
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
            is_224,
        }
    }

    /// 64바이트 데이터 블록을 처리하는 압축 함수(compression function)
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        // 메시지 스케줄(message schedule) 구성
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_256_K[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        // 연산 후 메시지 스케줄 w의 메모리 안전한 소거(zeroization)
        for item in w.iter_mut() {
            unsafe {
                write_volatile(item, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.total_len += (data.len() as u64) * 8;
        let mut i = 0;

        while i < data.len() {
            let fill = 64 - self.buffer_len;
            let chunk_len = core::cmp::min(data.len() - i, fill);

            self.buffer[self.buffer_len..self.buffer_len + chunk_len]
                .copy_from_slice(&data[i..i + chunk_len]);

            self.buffer_len += chunk_len;
            i += chunk_len;

            if self.buffer_len == 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&self.buffer);
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub(crate) fn finalize(mut self) -> Vec<u8> {
        // 1비트 '1' 패딩 추가(append 1 bit)
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // 길이가 56바이트를 초과하면 버퍼를 0으로 채우고 새로운 블록 처리
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..64].fill(0);
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer);
            self.process_block(&block);
            self.buffer_len = 0;
        }

        // 남은 버퍼 공간을 0으로 채우기
        self.buffer[self.buffer_len..56].fill(0);

        // 최종 64비트 길이를 빅 엔디안 형식으로 추가(append length in big-endian)
        self.buffer[56..64].copy_from_slice(&self.total_len.to_be_bytes());

        let mut block = [0u8; 64];
        block.copy_from_slice(&self.buffer);
        self.process_block(&block);

        let mut digest = Vec::with_capacity(32);
        for &s in &self.state {
            digest.extend_from_slice(&s.to_be_bytes());
        }

        if self.is_224 {
            digest.truncate(28);
        }

        // self가 범위를 벗어나면서 Drop 트레이트에 의해 내부 상태가 자동 소거됨
        digest
    }
}
