//! RFC 9106 준수 Argon2id 패스워드 해시 함수 모듈입니다.
//!
//! BLAKE2b를 내부 해시 함수로 사용하며, 메모리 경화(memory-hardness)를
//! 통해 GPU/ASIC 공격을 방어합니다. NIST SP 800-63B 권고를 준수합니다.
//!
//! # Security Note
//! - 패스워드와 최종 태그는 `SecureBuffer`(mlock)에 보관됩니다.
//! - 모든 메모리 블록은 연산 완료 후 `write_volatile`로 강제 소거됩니다.
//! - BLAMKA 64비트 곱셈이 ASIC 저항을 제공합니다.
//! - Argon2id 하이브리드 모드: 패스 0 슬라이스 0-1(Argon2i) + 나머지(Argon2d).
//!
//! # Examples
//! ```
//! use entlib_native_argon2id::Argon2id;
//!
//! let params = Argon2id::new(1, 8192, 1, 32).unwrap();
//! let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
//! assert_eq!(tag.as_slice().len(), 32);
//! ```

mod blamka;

use blamka::block_g;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_blake::{Blake2b, blake2b_long};
use entlib_native_secure_buffer::SecureBuffer;

const ARGON2ID_TYPE: u32 = 2;
const ARGON2_VERSION: u32 = 0x13;
const SYNC_POINTS: usize = 4;

/// Argon2id 파라미터 및 해시 연산 구조체입니다.
pub struct Argon2id {
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    tag_length: u32,
}

impl Argon2id {
    /// Argon2id 인스턴스를 생성하는 함수입니다.
    ///
    /// # Errors
    /// 파라미터가 RFC 9106 범위를 벗어나면 `Err`.
    pub fn new(
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
        tag_length: u32,
    ) -> Result<Self, &'static str> {
        if parallelism == 0 || parallelism > 0x00FF_FFFF {
            return Err("parallelism must be 1..=2^24-1");
        }
        if time_cost == 0 {
            return Err("time_cost must be >= 1");
        }
        if memory_cost < 8 * parallelism {
            return Err("memory_cost must be >= 8*parallelism");
        }
        if tag_length < 4 {
            return Err("tag_length must be >= 4");
        }
        Ok(Self {
            time_cost,
            memory_cost,
            parallelism,
            tag_length,
        })
    }

    /// 패스워드를 해시하여 태그를 SecureBuffer로 반환하는 함수입니다.
    ///
    /// # Arguments
    /// - `password` — 해시할 패스워드
    /// - `salt` — 솔트 (최소 8바이트)
    /// - `secret` — 추가 비밀 값 (0..=32 bytes, 선택)
    /// - `ad` — 연관 데이터 (선택)
    ///
    /// # Errors
    /// 솔트 < 8바이트 또는 SecureBuffer 할당 실패 시 `Err`.
    pub fn hash(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        ad: &[u8],
    ) -> Result<SecureBuffer, &'static str> {
        if salt.len() < 8 {
            return Err("salt must be >= 8 bytes");
        }

        let p = self.parallelism as usize;
        let t = self.time_cost as usize;
        let m = self.memory_cost as usize;

        // m' = floor(m/(4p)) * 4p — 4p의 배수
        let m_prime = (m / (4 * p)) * (4 * p);
        let q = m_prime / p; // 레인당 블록 수
        let sl = q / SYNC_POINTS; // 세그먼트 길이

        if sl < 2 {
            return Err("memory_cost too small for given parallelism");
        }

        // H0: 초기 512비트 해시
        let h0 = compute_h0(
            p as u32,
            self.tag_length,
            m as u32,
            t as u32,
            ARGON2_VERSION,
            ARGON2ID_TYPE,
            password,
            salt,
            secret,
            ad,
        )?;

        // 메모리 할당
        let total = p * q;
        let mut blocks: Vec<[u64; 128]> = vec![[0u64; 128]; total];

        // 초기 두 블록 초기화
        for lane in 0..p {
            let h0_0 = concat_h0(h0.as_slice(), 0u32, lane as u32);
            let b0 = blake2b_long(&h0_0, 1024)?;
            copy_to_block(&mut blocks[lane * q], b0.as_slice());

            let h0_1 = concat_h0(h0.as_slice(), 1u32, lane as u32);
            let b1 = blake2b_long(&h0_1, 1024)?;
            copy_to_block(&mut blocks[lane * q + 1], b1.as_slice());
        }

        // 패스 채우기
        for pass in 0..t {
            for slice in 0..SYNC_POINTS {
                for lane in 0..p {
                    fill_segment(&mut blocks, pass, slice, lane, p, q, sl, t);
                }
            }
        }

        // 최종화
        // C = XOR of B[i][q-1]
        let mut c = blocks[q - 1];
        for lane in 1..p {
            let b = blocks[lane * q + (q - 1)];
            for i in 0..128 {
                c[i] ^= b[i];
            }
        }

        let c_bytes = block_to_bytes(&c);
        let tag = blake2b_long(&c_bytes, self.tag_length as usize)?;

        // 메모리 소거
        for block in &mut blocks {
            for word in block.iter_mut() {
                unsafe { write_volatile(word, 0u64) };
            }
        }
        compiler_fence(Ordering::SeqCst);

        Ok(tag)
    }
}

//
// 세그먼트 채우기
//

#[allow(clippy::too_many_arguments)]
fn fill_segment(
    blocks: &mut [[u64; 128]],
    pass: usize,
    slice: usize,
    lane: usize,
    p: usize,
    q: usize,
    sl: usize,
    t: usize,
) {
    // Argon2id: 패스 0, 슬라이스 0-1 = 데이터 독립(Argon2i), 나머지 = Argon2d
    let data_independent = pass == 0 && slice < 2;

    let mut addr_input = [0u64; 128];
    let mut addr_block = [0u64; 128];

    if data_independent {
        addr_input[0] = pass as u64;
        addr_input[1] = lane as u64;
        addr_input[2] = slice as u64;
        addr_input[3] = (p * q) as u64;
        addr_input[4] = t as u64;
        addr_input[5] = ARGON2ID_TYPE as u64;
        addr_input[6] = 0;
    }

    let start_col = if pass == 0 && slice == 0 { 2 } else { 0 };

    for col_in_seg in start_col..sl {
        let col = slice * sl + col_in_seg;
        let cur_idx = lane * q + col;
        let prev_col = if col == 0 { q - 1 } else { col - 1 };
        let prev_idx = lane * q + prev_col;

        // 의사난수 취득
        let pseudo_rand: u64 = if data_independent {
            if col_in_seg % 128 == 0 {
                addr_input[6] += 1;
                let zero = [0u64; 128];
                let mut tmp = [0u64; 128];
                block_g(&mut tmp, &zero, &addr_input, false);
                block_g(&mut addr_block, &zero, &tmp, false);
            }
            addr_block[col_in_seg % 128]
        } else {
            blocks[prev_idx][0]
        };

        let j1 = pseudo_rand & 0xFFFF_FFFF;
        let j2 = pseudo_rand >> 32;

        // 참조 레인
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            (j2 as usize) % p
        };

        let same_lane = ref_lane == lane;

        // 참조 영역 크기
        let ref_area: usize = if pass == 0 {
            if slice == 0 {
                col_in_seg.saturating_sub(1)
            } else if same_lane {
                slice * sl + col_in_seg - 1
            } else {
                slice * sl - usize::from(col_in_seg == 0)
            }
        } else if same_lane {
            q - sl + col_in_seg - 1
        } else {
            q - sl - usize::from(col_in_seg == 0)
        };

        // phi 함수 → 참조 열 인덱스
        let ref_col = if ref_area == 0 {
            0
        } else {
            let x = j1.wrapping_mul(j1) >> 32;
            let y = (ref_area as u64).wrapping_mul(x) >> 32;
            let relative = ref_area - 1 - y as usize;
            let start = if pass == 0 || slice == SYNC_POINTS - 1 {
                0
            } else {
                (slice + 1) * sl
            };
            (start + relative) % q
        };

        let ref_idx = ref_lane * q + ref_col;
        let xor = pass > 0;

        // G(B_prev, B_ref) → B_cur
        // 인덱스 충돌 방지: 임시 복사 사용
        let prev_copy = blocks[prev_idx];
        let ref_copy = blocks[ref_idx];
        block_g(&mut blocks[cur_idx], &prev_copy, &ref_copy, xor);
    }
}

//
// 헬퍼
//

#[allow(clippy::too_many_arguments)]
fn compute_h0(
    parallelism: u32,
    tag_length: u32,
    memory_cost: u32,
    time_cost: u32,
    version: u32,
    argon2_type: u32,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
) -> Result<SecureBuffer, &'static str> {
    let mut h = Blake2b::new(64);
    h.update(&parallelism.to_le_bytes());
    h.update(&tag_length.to_le_bytes());
    h.update(&memory_cost.to_le_bytes());
    h.update(&time_cost.to_le_bytes());
    h.update(&version.to_le_bytes());
    h.update(&argon2_type.to_le_bytes());
    h.update(&(password.len() as u32).to_le_bytes());
    h.update(password);
    h.update(&(salt.len() as u32).to_le_bytes());
    h.update(salt);
    h.update(&(secret.len() as u32).to_le_bytes());
    h.update(secret);
    h.update(&(ad.len() as u32).to_le_bytes());
    h.update(ad);
    h.finalize()
}

fn concat_h0(h0: &[u8], idx: u32, lane: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(h0.len() + 8);
    v.extend_from_slice(h0);
    v.extend_from_slice(&idx.to_le_bytes());
    v.extend_from_slice(&lane.to_le_bytes());
    v
}

fn copy_to_block(block: &mut [u64; 128], bytes: &[u8]) {
    for (i, word) in block.iter_mut().enumerate() {
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
}

fn block_to_bytes(block: &[u64; 128]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1024);
    for word in block {
        v.extend_from_slice(&word.to_le_bytes());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9106 Appendix B.4 테스트 벡터
    // t=3, m=32 (32 KiB), p=4, tag_length=32
    #[test]
    fn rfc9106_test_vector() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];

        let params = Argon2id::new(3, 32, 4, 32).unwrap();
        let tag = params.hash(&password, &salt, &secret, &ad).unwrap();

        let expected = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(
            tag.as_slice(),
            &expected,
            "RFC 9106 test vector mismatch\ngot:  {:02x?}\nwant: {:02x?}",
            tag.as_slice(),
            &expected
        );
    }

    #[test]
    fn basic_hash_length() {
        let params = Argon2id::new(1, 64, 1, 32).unwrap();
        let tag = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
        assert_eq!(tag.as_slice().len(), 32);
    }

    #[test]
    fn different_passwords_give_different_tags() {
        let params = Argon2id::new(1, 64, 1, 32).unwrap();
        let t1 = params.hash(b"password1", b"somesalt", &[], &[]).unwrap();
        let t2 = params.hash(b"password2", b"somesalt", &[], &[]).unwrap();
        assert_ne!(t1.as_slice(), t2.as_slice());
    }

    #[test]
    fn different_salts_give_different_tags() {
        let params = Argon2id::new(1, 64, 1, 32).unwrap();
        let t1 = params.hash(b"password", b"somesalt", &[], &[]).unwrap();
        let t2 = params.hash(b"password", b"otherslt", &[], &[]).unwrap();
        assert_ne!(t1.as_slice(), t2.as_slice());
    }

    #[test]
    fn salt_too_short_rejected() {
        let params = Argon2id::new(1, 64, 1, 32).unwrap();
        assert!(params.hash(b"password", b"short", &[], &[]).is_err());
    }

    #[test]
    fn invalid_params_rejected() {
        assert!(Argon2id::new(0, 64, 1, 32).is_err()); // time_cost = 0
        assert!(Argon2id::new(1, 4, 1, 32).is_err()); // memory too small
        assert!(Argon2id::new(1, 64, 0, 32).is_err()); // parallelism = 0
        assert!(Argon2id::new(1, 64, 1, 3).is_err()); // tag_length < 4
    }
}
