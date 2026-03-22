//! AES-256 블록 암호 코어 모듈입니다.
//! 룩업 테이블 없이 GF(2^8) 산술 연산만으로 구현하여 캐시-타이밍 부채널 공격을 차단합니다.
//!
//! # Examples
//! ```rust
//! use entlib_native_aes::{AES256GCM, GCM_NONCE_LEN, GCM_TAG_LEN};
//! use entlib_native_secure_buffer::SecureBuffer;
//!
//! let mut key = SecureBuffer::new_owned(32).unwrap();
//! key.as_mut_slice().copy_from_slice(&[0u8; 32]);
//! let nonce = [0u8; GCM_NONCE_LEN];
//! let plaintext = b"hello world";
//! let mut ct = vec![0u8; plaintext.len()];
//! let mut tag = [0u8; GCM_TAG_LEN];
//! AES256GCM::encrypt(&key, &nonce, &[], plaintext, &mut ct, &mut tag).unwrap();
//! ```

use core::ptr::write_volatile;

pub type Block = [u8; 16];

// AES-256 field 연산: x^8 + x^4 + x^3 + x + 1 (0x11b)
#[inline(always)]
fn xtime(a: u8) -> u8 {
    let mask = (a >> 7).wrapping_neg();
    (a << 1) ^ (0x1b & mask)
}

// GF(2^8) 곱셈 — 고정 8회 반복, 분기 없음
#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;
        let hi = (a >> 7).wrapping_neg();
        a = (a << 1) ^ (0x1b & hi);
        b >>= 1;
    }
    p
}

// GF(2^8) 역원: a^254 = a^(11111110b), a=0이면 0 반환 (분기 없음)
#[inline(always)]
fn gf_inv(a: u8) -> u8 {
    let a2 = gmul(a, a);
    let a4 = gmul(a2, a2);
    let a8 = gmul(a4, a4);
    let a16 = gmul(a8, a8);
    let a32 = gmul(a16, a16);
    let a64 = gmul(a32, a32);
    let a128 = gmul(a64, a64);
    gmul(
        gmul(gmul(gmul(gmul(gmul(a128, a64), a32), a16), a8), a4),
        a2,
    )
}

/// AES SubBytes 바이트 치환 함수입니다.
/// GF(2^8) 역원(a^254) 계산 후 아핀 변환을 적용하여 S-Box 출력을 반환합니다.
#[inline(always)]
pub fn sub_byte(a: u8) -> u8 {
    let inv = gf_inv(a);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

// InvSubBytes: 역 아핀 후 역원
#[inline(always)]
fn inv_sub_byte(a: u8) -> u8 {
    let t = a.rotate_left(1) ^ a.rotate_left(3) ^ a.rotate_left(6) ^ 0x05;
    gf_inv(t)
}

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        sub_byte(b[0]),
        sub_byte(b[1]),
        sub_byte(b[2]),
        sub_byte(b[3]),
    ])
}

fn sub_bytes(state: &mut Block) {
    for b in state.iter_mut() {
        *b = sub_byte(*b);
    }
}

fn inv_sub_bytes(state: &mut Block) {
    for b in state.iter_mut() {
        *b = inv_sub_byte(*b);
    }
}

// 상태: 열 우선(column-major). state[col*4 + row]
// ShiftRows: row r을 왼쪽으로 r칸 회전
fn shift_rows(state: &mut Block) {
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    state.swap(2, 10);
    state.swap(6, 14);

    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

fn inv_shift_rows(state: &mut Block) {
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;

    state.swap(2, 10);
    state.swap(6, 14);

    let t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

// MixColumns: [2 3 1 1 / 1 2 3 1 / 1 1 2 3 / 3 1 1 2] × column
fn mix_columns(state: &mut Block) {
    for col in 0..4 {
        let b = col * 4;
        let (s0, s1, s2, s3) = (state[b], state[b + 1], state[b + 2], state[b + 3]);
        state[b] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[b + 1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[b + 2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[b + 3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

// InvMixColumns: [14 11 13 9 / 9 14 11 13 / 13 9 14 11 / 11 13 9 14] × column
fn inv_mix_columns(state: &mut Block) {
    #[inline(always)]
    fn m9(a: u8) -> u8 {
        xtime(xtime(xtime(a))) ^ a
    }
    #[inline(always)]
    fn m11(a: u8) -> u8 {
        xtime(xtime(xtime(a))) ^ xtime(a) ^ a
    }
    #[inline(always)]
    fn m13(a: u8) -> u8 {
        xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a
    }
    #[inline(always)]
    fn m14(a: u8) -> u8 {
        xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a)
    }

    for col in 0..4 {
        let b = col * 4;
        let (s0, s1, s2, s3) = (state[b], state[b + 1], state[b + 2], state[b + 3]);
        state[b] = m14(s0) ^ m11(s1) ^ m13(s2) ^ m9(s3);
        state[b + 1] = m9(s0) ^ m14(s1) ^ m11(s2) ^ m13(s3);
        state[b + 2] = m13(s0) ^ m9(s1) ^ m14(s2) ^ m11(s3);
        state[b + 3] = m11(s0) ^ m13(s1) ^ m9(s2) ^ m14(s3);
    }
}

#[inline(always)]
fn add_round_key(state: &mut Block, rk: &Block) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

// AES-256 Rcon: i/8 = 1..7 → index 0..6
const RCON: [u32; 7] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
];

/// AES-256 키 스케줄 구조체입니다.
/// 256비트 키로부터 15개의 라운드 키를 파생하며, `Drop` 시 모든 라운드 키를 소거합니다.
pub struct KeySchedule {
    pub round_keys: [Block; 15],
}

impl KeySchedule {
    /// AES-256 키 스케줄을 생성하는 함수입니다.
    ///
    /// # Arguments
    /// `key` — 256비트(32 bytes) AES 키
    pub fn new(key: &[u8; 32]) -> Self {
        let mut w = [0u32; 60];

        for i in 0..8 {
            w[i] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - 8] ^ temp;
        }

        let mut round_keys = [[0u8; 16]; 15];
        for rk in 0..15 {
            for j in 0..4 {
                let bytes = w[rk * 4 + j].to_be_bytes();
                round_keys[rk][j * 4] = bytes[0];
                round_keys[rk][j * 4 + 1] = bytes[1];
                round_keys[rk][j * 4 + 2] = bytes[2];
                round_keys[rk][j * 4 + 3] = bytes[3];
            }
        }

        // w에 잔존하는 키 파생 중간값 소거
        for word in &mut w {
            unsafe { write_volatile(word, 0) };
        }

        Self { round_keys }
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            for b in rk {
                unsafe { write_volatile(b, 0) };
            }
        }
    }
}

/// AES-256 블록 암호화 함수입니다.
/// 14라운드 순방향 암호(SubBytes → ShiftRows → MixColumns → AddRoundKey)를 수행합니다.
///
/// # Arguments
/// - `state` — 입출력 16바이트 블록 (in-place)
/// - `ks` — 사전 생성된 키 스케줄
pub fn aes256_encrypt_block(state: &mut Block, ks: &KeySchedule) {
    add_round_key(state, &ks.round_keys[0]);
    for round in 1..14 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ks.round_keys[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ks.round_keys[14]);
}

/// 단일 블록 ECB 암호화 함수입니다. KAT(Known Answer Test) 전용입니다.
///
/// # Security Note
/// ECB 모드는 패턴을 보존하므로 실제 암호화에 사용할 수 없습니다.
#[cfg_attr(not(test), allow(dead_code))]
pub fn aes256_encrypt_ecb(key: &[u8; 32], plaintext: &[u8; 16]) -> Block {
    let ks = KeySchedule::new(key);
    let mut state = *plaintext;
    aes256_encrypt_block(&mut state, &ks);
    state
}

/// AES-256 블록 복호화 함수입니다.
/// 14라운드 역방향 암호(InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns)를 수행합니다.
///
/// # Arguments
/// - `state` — 입출력 16바이트 블록 (in-place)
/// - `ks` — 사전 생성된 키 스케줄
pub fn aes256_decrypt_block(state: &mut Block, ks: &KeySchedule) {
    add_round_key(state, &ks.round_keys[14]);
    for round in (1..14).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ks.round_keys[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ks.round_keys[0]);
}
