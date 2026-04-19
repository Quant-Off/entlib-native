use core::ptr::write_volatile;
use entlib_native_hmac::{
    HMACSHA3_224, HMACSHA3_256, HMACSHA3_384, HMACSHA3_512, HMACSHA224, HMACSHA256, HMACSHA384,
    HMACSHA512,
};
use entlib_native_secure_buffer::SecureBuffer;

// NIST SP 800-132 Section 5.1: Salt 최소 길이 = 128 bits
const MIN_SALT_LEN: usize = 16;
// NIST SP 800-132 Section 5.2: 반복 횟수 최소 권고값
const MIN_ITERATIONS: u32 = 1_000;

/// NIST SP 800-132 PBKDF2 연산 중 발생할 수 있는 오류
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Error {
    /// Salt 길이가 NIST SP 800-132 Section 5.1 요구사항(최소 128 bits / 16 bytes) 미달
    WeakSalt,
    /// 반복 횟수가 NIST SP 800-132 Section 5.2 권고값(최소 1,000) 미달
    InsufficientIterations,
    /// DK 길이가 0이거나 NIST SP 800-132 최대값((2^32 - 1) * hLen) 초과
    InvalidDkLength,
    /// 패스워드 길이가 NIST SP 800-107r1 최소 키 길이(112 bits / 14 bytes) 미달
    WeakPassword,
    /// 내부 HMAC 연산 실패
    HmacError,
}

macro_rules! impl_pbkdf2 {
    ($struct_name:ident, $hmac_type:ty, $hash_len:expr) => {
        /// NIST SP 800-132를 준수하는 PBKDF2 인스턴스
        pub struct $struct_name;

        impl Default for $struct_name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $struct_name {
            pub const HASH_LEN: usize = $hash_len;
            /// NIST SP 800-132 Section 5.3: DK 최대 길이 = (2^32 - 1) * hLen
            pub const MAX_DK_LEN: u64 = (u32::MAX as u64) * ($hash_len as u64);

            pub fn new() -> Self {
                Self
            }

            /// NIST SP 800-132 Section 5: PBKDF2 키 유도
            ///
            /// `password`로부터 `dk`에 파생 키를 출력합니다.
            ///
            /// # Arguments
            /// - `password` - 패스워드 (SecureBuffer, 최소 112 bits / 14 bytes)
            /// - `salt` - 솔트 (최소 128 bits / 16 bytes, NIST SP 800-132 Section 5.1)
            /// - `iterations` - PRF 반복 횟수 (최소 1,000, NIST SP 800-132 Section 5.2)
            /// - `dk` - 파생 키를 저장할 출력 버퍼 (최대 (2^32-1) * hLen bytes)
            ///
            /// # Security Note
            /// 중간값(U 블록, T 블록)은 스택에서 연산 후 `write_volatile`로 강제 소거됩니다.
            /// 패스워드는 호출자가 `SecureBuffer`로 관리해야 합니다.
            pub fn derive_key(
                &self,
                password: &SecureBuffer,
                salt: &[u8],
                iterations: u32,
                dk: &mut [u8],
            ) -> Result<(), Pbkdf2Error> {
                if salt.len() < MIN_SALT_LEN {
                    return Err(Pbkdf2Error::WeakSalt);
                }
                if iterations < MIN_ITERATIONS {
                    return Err(Pbkdf2Error::InsufficientIterations);
                }
                let dk_len = dk.len();
                if dk_len == 0 || dk_len as u64 > Self::MAX_DK_LEN {
                    return Err(Pbkdf2Error::InvalidDkLength);
                }

                let block_count = dk_len.div_ceil(Self::HASH_LEN);
                let mut offset: usize = 0;

                for i in 0..block_count {
                    let block_index = (i as u32).wrapping_add(1);
                    let copy_len = core::cmp::min(Self::HASH_LEN, dk_len - offset);

                    // F(Password, Salt, c, i) = U_1 XOR U_2 XOR ... XOR U_c
                    let mut t = [0u8; $hash_len];
                    let mut u = [0u8; $hash_len];

                    // U_1 = PRF(Password, Salt || INT(i))
                    {
                        let mut hmac = <$hmac_type>::new(password.as_slice()).map_err(|e| {
                            use entlib_native_hmac::HmacError;
                            match e {
                                HmacError::WeakKeyLength => Pbkdf2Error::WeakPassword,
                                _ => Pbkdf2Error::HmacError,
                            }
                        })?;
                        hmac.update(salt);
                        hmac.update(&block_index.to_be_bytes());
                        let mac = hmac.finalize().map_err(|_| Pbkdf2Error::HmacError)?;
                        u.copy_from_slice(mac.as_slice());
                    }
                    t.copy_from_slice(&u);

                    // U_j = PRF(Password, U_{j-1}) for j = 2..=c
                    for _ in 1..iterations {
                        let mut hmac = <$hmac_type>::new(password.as_slice())
                            .map_err(|_| Pbkdf2Error::HmacError)?;
                        hmac.update(&u);
                        let mac = hmac.finalize().map_err(|_| Pbkdf2Error::HmacError)?;
                        u.copy_from_slice(mac.as_slice());

                        // XOR 누산: 상수-시간 연산
                        for j in 0..$hash_len {
                            t[j] ^= u[j];
                        }
                    }

                    dk[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
                    offset += copy_len;

                    // 중간값 강제 소거
                    for byte in &mut t {
                        unsafe { write_volatile(byte, 0) };
                    }
                    for byte in &mut u {
                        unsafe { write_volatile(byte, 0) };
                    }
                }

                Ok(())
            }
        }
    };
}

impl_pbkdf2!(PBKDF2HMACSHA224, HMACSHA224, 28);
impl_pbkdf2!(PBKDF2HMACSHA256, HMACSHA256, 32);
impl_pbkdf2!(PBKDF2HMACSHA384, HMACSHA384, 48);
impl_pbkdf2!(PBKDF2HMACSHA512, HMACSHA512, 64);

impl_pbkdf2!(PBKDF2HMACSHA3_224, HMACSHA3_224, 28);
impl_pbkdf2!(PBKDF2HMACSHA3_256, HMACSHA3_256, 32);
impl_pbkdf2!(PBKDF2HMACSHA3_384, HMACSHA3_384, 48);
impl_pbkdf2!(PBKDF2HMACSHA3_512, HMACSHA3_512, 64);
