use core::cmp::min;
use core::ptr::write_volatile;
use entlib_native_hmac::{
    HMACSHA3_224, HMACSHA3_256, HMACSHA3_384, HMACSHA3_512, HMACSHA224, HMACSHA256, HMACSHA384,
    HMACSHA512,
};
use entlib_native_secure_buffer::SecureBuffer;

/// HKDF 연산 중 발생할 수 있는 상태 및 오류를 정의합니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HKDFState {
    Success,
    /// 요청된 OKM 길이가 최대 제한을 초과했거나 입력 버퍼가 잘못된 경우
    InvalidLength,
    /// 보안 버퍼(SecureBuffer) 할당 실패 또는 OS 메모리 잠금 실패
    AllocationFailed,
    /// 내부 HMAC 연산 실패
    HmacError,
}

macro_rules! impl_hkdf {
    (
        $struct_name:ident,
        $hmac_type:ty,
        $hash_len:expr
    ) => {
        /// NIST SP 800-56Cr2를 준수하는 HKDF 인스턴스
        pub struct $struct_name;

        impl Default for $struct_name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $struct_name {
            /// 이 HKDF 구현에서 사용하는 기반 해시 함수의 출력 크기 (바이트)
            pub const HASH_LEN: usize = $hash_len;
            /// RFC 5869에 따른 OKM 최대 출력 크기 제한 (255 * HashLen)
            pub const MAX_OKM_LEN: usize = 255 * $hash_len;

            /// 새로운 HKDF 인스턴스를 생성합니다.
            #[inline(always)]
            pub fn new() -> Self {
                Self
            }

            /// Extract (추출)
            ///
            /// 입력된 키 구성 물질(IKM)과 Salt를 사용하여 고정된 길이의 의사난수 키(PRK)를 생성합니다.
            ///
            /// 반환되는 PRK는 `SecureBuffer`에 안전하게 보관되어,
            /// 메모리 스왑 방지 및 사용 후 즉각적인 Zeroization이 보장됩니다.
            pub fn extract(
                &self,
                salt: Option<&[u8]>,
                ikm: &[u8],
            ) -> Result<SecureBuffer, HKDFState> {
                let default_salt = [0u8; $hash_len];
                let actual_salt = salt.unwrap_or(&default_salt);

                let mut hmac = <$hmac_type>::new(actual_salt).map_err(|_| HKDFState::HmacError)?;
                hmac.update(ikm);
                let prk_mac = hmac.finalize().map_err(|_| HKDFState::HmacError)?;

                // PRK는 SecureBuffer를 통해 관리
                let mut prk_buffer =
                    SecureBuffer::new_owned($hash_len).map_err(|_| HKDFState::AllocationFailed)?;
                prk_buffer
                    .as_mut_slice()
                    .copy_from_slice(prk_mac.as_slice());

                Ok(prk_buffer)
            }

            /// Expand (확장)
            ///
            /// PRK와 컨텍스트(info)를 결합하여 원하는 길이(length)의 출력 키 물질(OKM)을 생성합니다.
            pub fn expand(
                &self,
                prk: &SecureBuffer,
                okm: &mut [u8],
                info: &[u8],
                length: usize,
            ) -> Result<(), HKDFState> {
                // 입력 길이 및 버퍼 크기에 대한 엄격한 검증
                if length > Self::MAX_OKM_LEN || okm.len() < length {
                    return Err(HKDFState::InvalidLength);
                }
                if prk.len() < Self::HASH_LEN {
                    return Err(HKDFState::InvalidLength);
                }

                let mut t = [0u8; $hash_len];
                let mut okm_offset = 0;
                let mut block_index: u8 = 1;

                let n = length.div_ceil(Self::HASH_LEN);

                for i in 0..n {
                    let mut hmac =
                        <$hmac_type>::new(prk.as_slice()).map_err(|_| HKDFState::HmacError)?;

                    if i > 0 {
                        hmac.update(&t);
                    }
                    hmac.update(info);
                    hmac.update(&[block_index]);

                    let mac = hmac.finalize().map_err(|_| HKDFState::HmacError)?;
                    t.copy_from_slice(mac.as_slice());

                    let copy_len = min(Self::HASH_LEN, length - okm_offset);
                    okm[okm_offset..okm_offset + copy_len].copy_from_slice(&t[..copy_len]);

                    okm_offset += copy_len;
                    block_index += 1;
                }

                // T 블록 강제 소거
                for byte in &mut t {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                Ok(())
            }

            /// 단일 단계 키 유도 (Extract-then-Expand)
            ///
            /// IKM과 Salt를 사용해 내부적으로 PRK를 추출한 뒤, 즉시 Context(info)와 결합하여
            /// 원하는 길이의 출력 키 물질(OKM)을 생성합니다.
            ///
            /// # Security Rationale
            /// 내부적으로 생성된 PRK(`SecureBuffer`)는 반환과 동시에 스코프를 벗어나며,
            /// `Drop` 트레이트를 통해 즉시 하드웨어 수준에서 강제 소거(Zeroize)됩니다.
            pub fn derive_key(
                &self,
                salt: Option<&[u8]>,
                ikm: &[u8],
                okm: &mut [u8],
                info: &[u8],
                length: usize,
            ) -> Result<(), HKDFState> {
                // Extract (PRK 생성 및 잠긴 메모리에 보관)
                let prk_buffer = self.extract(salt, ikm)?;

                // Expand (PRK를 사용하여 OKM 생성)
                // okm 버퍼의 크기 검증 등은 내부 expand 메소드의 Zero-Trust 로직에 위임
                self.expand(&prk_buffer, okm, info, length)
            }
        }
    };
}

impl_hkdf!(HKDFSHA224, HMACSHA224, 28);
impl_hkdf!(HKDFSHA256, HMACSHA256, 32);
impl_hkdf!(HKDFSHA384, HMACSHA384, 48);
impl_hkdf!(HKDFSHA512, HMACSHA512, 64);

impl_hkdf!(HKDFSHA3_224, HMACSHA3_224, 28);
impl_hkdf!(HKDFSHA3_256, HMACSHA3_256, 32);
impl_hkdf!(HKDFSHA3_384, HMACSHA3_384, 48);
impl_hkdf!(HKDFSHA3_512, HMACSHA3_512, 64);
