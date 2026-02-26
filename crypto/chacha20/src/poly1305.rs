use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_constant_time::constant_time::ConstantTimeOps;
use entlib_native_core_secure::secure_buffer::SecureBuffer;

/// 내부 연산을 위해 캡슐화된 Poly1305 상태(state) 구조체입니다.
/// 메모리 안전성을 위해 스코프를 벗어날 때 즉각적으로 데이터를 소거(zeroize)합니다.
struct Poly1305State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305State {
    #[inline(always)]
    fn new(key: &[u8; 32]) -> Self {
        // 상수-시간 클램핑(clamping) 적용
        let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(key[12..16].try_into().unwrap());

        let r0 = t0 & 0x03ffffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ffff03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f03fff;
        let r4 = (t3 >> 8) & 0x000fffff;

        let pad0 = u32::from_le_bytes(key[16..20].try_into().unwrap());
        let pad1 = u32::from_le_bytes(key[20..24].try_into().unwrap());
        let pad2 = u32::from_le_bytes(key[24..28].try_into().unwrap());
        let pad3 = u32::from_le_bytes(key[28..32].try_into().unwrap());

        Self {
            r: [r0, r1, r2, r3, r4],
            h: [0; 5],
            pad: [pad0, pad1, pad2, pad3],
        }
    }

    #[inline(always)]
    fn process_block(&mut self, block: &[u8; 16], is_full: u8) {
        let m0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let m1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let m2 = u32::from_le_bytes(block[8..12].try_into().unwrap());
        let m3 = u32::from_le_bytes(block[12..16].try_into().unwrap());

        // Radix-26 분할 및 129번째 비트(패딩) 병합
        let limb0 = m0 & 0x03ffffff;
        let limb1 = ((m0 >> 26) | (m1 << 6)) & 0x03ffffff;
        let limb2 = ((m1 >> 20) | (m2 << 12)) & 0x03ffffff;
        let limb3 = ((m2 >> 14) | (m3 << 18)) & 0x03ffffff;
        let mut limb4 = m3 >> 8;

        // 전체 블록일 경우에만 129번째 비트를 추가 (CT MUX 사용)
        let pad_bit = 1u32 << 24;
        let mask = (is_full as u32).wrapping_neg(); // 1 -> 0xFFFFFFFF, 0 -> 0x00000000
        limb4 |= pad_bit.ct_select(0, mask);

        self.h[0] += limb0;
        self.h[1] += limb1;
        self.h[2] += limb2;
        self.h[3] += limb3;
        self.h[4] += limb4;

        let s1 = self.r[1] * 5;
        let s2 = self.r[2] * 5;
        let s3 = self.r[3] * 5;
        let s4 = self.r[4] * 5;

        // u64 캐스팅을 통한 오버플로우 방지 모듈러 곱셈
        let d0 = (self.h[0] as u64 * self.r[0] as u64)
            + (self.h[1] as u64 * s4 as u64)
            + (self.h[2] as u64 * s3 as u64)
            + (self.h[3] as u64 * s2 as u64)
            + (self.h[4] as u64 * s1 as u64);
        let d1 = (self.h[0] as u64 * self.r[1] as u64)
            + (self.h[1] as u64 * self.r[0] as u64)
            + (self.h[2] as u64 * s4 as u64)
            + (self.h[3] as u64 * s3 as u64)
            + (self.h[4] as u64 * s2 as u64);
        let d2 = (self.h[0] as u64 * self.r[2] as u64)
            + (self.h[1] as u64 * self.r[1] as u64)
            + (self.h[2] as u64 * self.r[0] as u64)
            + (self.h[3] as u64 * s4 as u64)
            + (self.h[4] as u64 * s3 as u64);
        let d3 = (self.h[0] as u64 * self.r[3] as u64)
            + (self.h[1] as u64 * self.r[2] as u64)
            + (self.h[2] as u64 * self.r[1] as u64)
            + (self.h[3] as u64 * self.r[0] as u64)
            + (self.h[4] as u64 * s4 as u64);
        let d4 = (self.h[0] as u64 * self.r[4] as u64)
            + (self.h[1] as u64 * self.r[3] as u64)
            + (self.h[2] as u64 * self.r[2] as u64)
            + (self.h[3] as u64 * self.r[1] as u64)
            + (self.h[4] as u64 * self.r[0] as u64);

        // 캐리(carry) 전파
        let mut c = (d0 >> 26) as u32;
        self.h[0] = (d0 as u32) & 0x03ffffff;
        let d1_v = d1 + c as u64;
        c = (d1_v >> 26) as u32;
        self.h[1] = (d1_v as u32) & 0x03ffffff;
        let d2_v = d2 + c as u64;
        c = (d2_v >> 26) as u32;
        self.h[2] = (d2_v as u32) & 0x03ffffff;
        let d3_v = d3 + c as u64;
        c = (d3_v >> 26) as u32;
        self.h[3] = (d3_v as u32) & 0x03ffffff;
        let d4_v = d4 + c as u64;
        c = (d4_v >> 26) as u32;
        self.h[4] = (d4_v as u32) & 0x03ffffff;
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x03ffffff;
        self.h[1] += c;
    }

    #[inline(always)]
    fn finalize(mut self, output: &mut [u8; 16]) {
        // 잔여 캐리 완벽 전파
        let mut c = self.h[1] >> 26;
        self.h[1] &= 0x03ffffff;
        self.h[2] += c;
        c = self.h[2] >> 26;
        self.h[2] &= 0x03ffffff;
        self.h[3] += c;
        c = self.h[3] >> 26;
        self.h[3] &= 0x03ffffff;
        self.h[4] += c;
        c = self.h[4] >> 26;
        self.h[4] &= 0x03ffffff;
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x03ffffff;
        self.h[1] += c;

        // h + 5 모듈러 감산을 위한 임시 값 계산
        let mut g0 = self.h[0] + 5;
        c = g0 >> 26;
        g0 &= 0x03ffffff;
        let mut g1 = self.h[1] + c;
        c = g1 >> 26;
        g1 &= 0x03ffffff;
        let mut g2 = self.h[2] + c;
        c = g2 >> 26;
        g2 &= 0x03ffffff;
        let mut g3 = self.h[3] + c;
        c = g3 >> 26;
        g3 &= 0x03ffffff;
        let mut g4 = self.h[4] + c;

        // g4에서 2^130 (1 << 26)을 뺐을 때 음수인지 판별
        let sub = g4.wrapping_sub(1 << 26);
        let mask = sub.ct_is_negative();

        // 뺄셈 결과가 음수면 원래의 h를, 아니면 g를 선택
        g4 = sub.ct_select(g4, mask) & 0x03ffffff;
        let f0 = self.h[0].ct_select(g0, mask);
        let f1 = self.h[1].ct_select(g1, mask);
        let f2 = self.h[2].ct_select(g2, mask);
        let f3 = self.h[3].ct_select(g3, mask);
        let f4 = self.h[4].ct_select(g4, mask);

        // 32비트 결합
        let mut out0 = f0 | (f1 << 26);
        let mut out1 = (f1 >> 6) | (f2 << 20);
        let mut out2 = (f2 >> 12) | (f3 << 14);
        let mut out3 = (f3 >> 18) | (f4 << 8);

        // 패딩(pad) 값 상수-시간 병합
        let (v0, c0) = out0.overflowing_add(self.pad[0]);
        out0 = v0;
        let (v1, c1) = out1.overflowing_add(self.pad[1].wrapping_add(c0 as u32));
        out1 = v1;
        let (v2, c2) = out2.overflowing_add(self.pad[2].wrapping_add(c1 as u32));
        out2 = v2;
        let (v3, _) = out3.overflowing_add(self.pad[3].wrapping_add(c2 as u32));
        out3 = v3;

        output[0..4].copy_from_slice(&out0.to_le_bytes());
        output[4..8].copy_from_slice(&out1.to_le_bytes());
        output[8..12].copy_from_slice(&out2.to_le_bytes());
        output[12..16].copy_from_slice(&out3.to_le_bytes());
    }
}

impl Drop for Poly1305State {
    fn drop(&mut self) {
        for word in self
            .r
            .iter_mut()
            .chain(self.h.iter_mut())
            .chain(self.pad.iter_mut())
        {
            unsafe {
                write_volatile(word, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Poly1305 MAC을 생성합니다.
/// 연산 결과는 Java 힙의 생명주기와 분리된 `SecureBuffer`로 반환됩니다.
pub fn generate_poly1305(key: &[u8; 32], data: &[u8]) -> SecureBuffer {
    let mut state = Poly1305State::new(key);
    let mut chunks = data.chunks_exact(16);

    for chunk in chunks.by_ref() {
        let block: &[u8; 16] = chunk.try_into().unwrap();
        state.process_block(block, 1);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut pad_block = [0u8; 16];
        let rem_len = remainder.len();

        pad_block[..rem_len].copy_from_slice(&remainder[..rem_len]);
        pad_block[rem_len] = 1; // RFC 8439 잔여 블록 패딩 적용

        state.process_block(&pad_block, 0);

        for byte in pad_block.iter_mut() {
            unsafe {
                write_volatile(byte, 0);
            }
        }
    }

    let mut mac = [0u8; 16];
    state.finalize(&mut mac);

    let mut result = SecureBuffer {
        inner: vec![0u8; 16],
    };
    result.inner.copy_from_slice(&mac);

    for byte in mac.iter_mut() {
        unsafe {
            write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    result
}
