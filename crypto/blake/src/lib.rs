//! BLAKE2b 및 BLAKE3 암호 해시 함수 모듈입니다.
//!
//! BLAKE2b는 RFC 7693을 준수하며, BLAKE3는 공식 명세를 따릅니다.
//! 민감 데이터는 `SecureBuffer`(mlock)에 보관하며, Drop 시 내부 상태를
//! `write_volatile`로 강제 소거합니다.
//!
//! ---
//!
//! `blake2b` 해시는 `blake2`의 변형 중 하나로, 64비트 플랫폼(최신 서버,
//! PC)에 최적화되어 있으며, 최대 512비트의 다이제스트를 생성합니다. 추 후
//! 다중 코어를 활용하기 위한 병렬 처리를 지원하는 `blake2bp`, `blake2sp`
//! 를 지원할 예정입니다.
//!
//! `blake3` 해시는 2020년에 발표된 최신 버전으로, 내부적으로 머클
//! 트리(Merkle Tree) 구조를 채택하여 SIMD 명령어와 다중 스레딩을 통한
//! 극단적인 병렬 처리가 가능합니다. 이는 `blake2b`보다도 압도적으로 빠르며,
//! 단일 알고리즘으로 기존의 다양한 변형(다이제스트 크기 변경, 키 파생 등)을
//! 모두 커버하도록 설계되었습니다.
//!
//! # Examples
//! ```rust,ignore
//! use entlib_native_blake::{Blake2b, Blake3, blake2b_long};
//!
//! // blake2b
//! let mut h = Blake2b::new(32);
//! h.update(b"hello world");
//! let digest = h.finalize().unwrap();
//! assert_eq!(digest.as_slice().len(), 32);
//!
//! // blake3
//! let mut h = Blake3::new();
//! h.update(b"hello world");
//! let digest = h.finalize().unwrap();
//! assert_eq!(digest.as_slice().len(), 32);
//!
//! let out = blake2b_long(b"input", 80).unwrap();
//! assert_eq!(out.as_slice().len(), 80);
//! ```
//!
//! # Authors
//! Q. T. Felix

mod blake2b;
mod blake3;

pub use blake2b::Blake2b;
pub use blake3::{Blake3, OUT_LEN as BLAKE3_OUT_LEN};

use entlib_native_base::error::hash::HashError;
use entlib_native_secure_buffer::SecureBuffer;

/// RFC 9106 Section 3.2에서 정의된 가변 출력 BLAKE2b 함수입니다 (H').
///
/// Argon2id 블록 초기화 및 최종 태그 생성에 사용됩니다.
///
/// # Security Note
/// `out_len > 64`일 때 중간 다이제스트를 체인으로 연결합니다.
/// 각 단계의 중간값은 SecureBuffer에 보관됩니다.
///
/// # Errors
/// `out_len == 0` 또는 SecureBuffer 할당 실패 시 `Err`.
pub fn blake2b_long(input: &[u8], out_len: usize) -> Result<SecureBuffer, HashError> {
    if out_len == 0 {
        return Err(HashError::InvalidOutputLength);
    }

    let len_prefix = (out_len as u32).to_le_bytes();

    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&len_prefix);
        h.update(input);
        return h.finalize();
    }

    // out_len > 64
    // r = ceil(out_len/32) - 2  (number of full-64-byte intermediate hashes)
    // last_len = out_len - 32*r  (final hash length, always 33..=64)
    let r = out_len.div_ceil(32).saturating_sub(2);
    let last_len = out_len - 32 * r;

    let mut out = SecureBuffer::new_owned(out_len)?;
    let out_slice = out.as_mut_slice();

    // A_1 = BLAKE2b-64(LE32(out_len) || input)
    let mut h = Blake2b::new(64);
    h.update(&len_prefix);
    h.update(input);
    let mut prev = h.finalize()?;

    out_slice[..32].copy_from_slice(&prev.as_slice()[..32]);
    let mut written = 32usize;

    // A_2 .. A_r  (r-1 iterations, each 64 bytes, take first 32)
    for _ in 1..r {
        let mut h = Blake2b::new(64);
        h.update(prev.as_slice());
        let a = h.finalize()?;
        out_slice[written..written + 32].copy_from_slice(&a.as_slice()[..32]);
        written += 32;
        prev = a;
    }

    // A_{r+1} = BLAKE2b-last_len(A_r), write all last_len bytes
    let mut h = Blake2b::new(last_len);
    h.update(prev.as_slice());
    let a = h.finalize()?;
    out_slice[written..out_len].copy_from_slice(a.as_slice());

    Ok(out)
}
