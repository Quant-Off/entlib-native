use crate::HmacError;
use entlib_native_constant_time::traits::ConstantTimeEq;
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha2::api::{SHA224, SHA256, SHA384, SHA512};
use entlib_native_sha3::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const SHA224_256_BLOCK_SIZE: usize = 64; // 512 bits
const SHA384_512_BLOCK_SIZE: usize = 128; // 1024 bits
// SHA3 HMAC 블록 크기 = rate (NIST FIPS 202 기준)
const SHA3_224_BLOCK_SIZE: usize = 144; // rate = 1152 bits
const SHA3_256_BLOCK_SIZE: usize = 136; // rate = 1088 bits
const SHA3_384_BLOCK_SIZE: usize = 104; // rate = 832 bits
const SHA3_512_BLOCK_SIZE: usize = 72; // rate = 576 bits
const MIN_KEY_LEN: usize = 14; // 112 bits (NIST SP 800-107r1)

/// 생성된 MAC을 담는 래퍼 구조체입니다.
///
/// 내부 필드는 [`SecureBuffer`]로 관리되어, `Drop` 시점에 MAC 바이트가
/// 자동으로 0으로 소거되고 OS 레벨 메모리 잠금(mlock)이 해제됩니다.
pub struct MacResult(SecureBuffer);

impl MacResult {
    /// MAC 바이트를 읽기 전용 슬라이스로 반환합니다.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl PartialEq for MacResult {
    /// 부채널 공격(Timing Attack) 방지를 위해 검증된 constant-time 크레이트 활용.
    ///
    /// MAC 길이(공개 정보)를 먼저 확인한 후 바이트를 상수-시간으로 비교합니다.
    #[inline(never)]
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_slice();
        let b = other.0.as_slice();

        // MAC 길이는 공개 정보이므로 일반 분기 허용
        if a.len() != b.len() {
            return false;
        }

        let mut is_equal = 0xFFu8;
        for (x, y) in a.iter().zip(b.iter()) {
            is_equal &= x.ct_eq(y).unwrap_u8();
        }

        is_equal == 0xFF
    }
}

impl Eq for MacResult {}

macro_rules! impl_hmac_sha {
    (
        $struct_name:ident,
        $hasher_type:ty,
        $block_size:expr,
        $mac_size:expr
    ) => {
        /// HMAC 구조체
        pub struct $struct_name {
            i_key_pad: [u8; $block_size],
            o_key_pad: [u8; $block_size],
            hasher: $hasher_type,
        }

        impl $struct_name {
            /// HMAC 초기화 및 키 준비 함수입니다.
            pub fn new(key: &[u8]) -> Result<Self, HmacError> {
                // [Security Control] NIST SP 800-107r1 5.3절: 112비트 미만의 키 거부
                if key.len() < MIN_KEY_LEN {
                    return Err(HmacError::WeakKeyLength);
                }

                let mut k_block = [0u8; $block_size];

                // 키 길이가 블록 크기보다 길 경우 해싱 (RFC 2104)
                if key.len() > $block_size {
                    let mut key_hasher = <$hasher_type>::new();
                    key_hasher.update(key);
                    let hashed_key = key_hasher
                        .finalize()
                        .map_err(HmacError::HashComputationError)?;

                    let hash_slice = hashed_key.as_slice();
                    k_block[..hash_slice.len()].copy_from_slice(hash_slice);
                } else {
                    k_block[..key.len()].copy_from_slice(key);
                }

                let mut i_key_pad = [0u8; $block_size];
                let mut o_key_pad = [0u8; $block_size];

                for i in 0..$block_size {
                    i_key_pad[i] = k_block[i] ^ IPAD;
                    o_key_pad[i] = k_block[i] ^ OPAD;
                }

                // H(K XOR ipad, text)의 첫 단계: H에 i_key_pad 주입
                let mut hasher = <$hasher_type>::new();
                hasher.update(&i_key_pad);

                // 사용이 끝난 원본 키 블록은 즉시 소거
                core::hint::black_box({
                    k_block.fill(0);
                });

                Ok(Self {
                    i_key_pad,
                    o_key_pad,
                    hasher,
                })
            }

            /// 스트리밍 방식을 지원하는 데이터 업데이트 함수입니다.
            pub fn update(&mut self, data: &[u8]) {
                self.hasher.update(data);
            }

            /// 최종 MAC 계산 및 반환 함수입니다.
            pub fn finalize(mut self) -> Result<MacResult, HmacError> {
                // Q. T. Felix NOTE: 왜 Option을 안 쓰냐 -> 분기생성 가능성 있음 -> 부채널 공격 위험해집니다.
                //                   Drop 구현체의 부분 소유권 이동 금지 규칙을 우회하기 위해,
                //                   분기 없는 core::mem::replace를 사용하여 내부 Hasher의 소유권을 획득
                //                   이 과정은 상수-시간으로 동작하며 해당 공격을 방지합니다.
                let hasher = core::mem::replace(&mut self.hasher, <$hasher_type>::new());

                // 소유권이 이전된 hasher를 통해 첫 번째 해시 결과 획득
                let inner_hash = hasher.finalize().map_err(HmacError::HashComputationError)?;

                // H(K XOR opad, H(K XOR ipad, text))
                let mut outer_hasher = <$hasher_type>::new();
                outer_hasher.update(&self.o_key_pad);
                outer_hasher.update(inner_hash.as_slice());

                // 최종 해시 결과 획득
                let outer_hash = outer_hasher
                    .finalize()
                    .map_err(HmacError::HashComputationError)?;

                // SecureBuffer에 MAC을 복사하여 mlock + 자동 소거 보장
                let mut mac_buf =
                    SecureBuffer::new_owned($mac_size).map_err(HmacError::AllocationError)?;
                mac_buf
                    .as_mut_slice()
                    .copy_from_slice(outer_hash.as_slice());

                Ok(MacResult(mac_buf))
            }
        }

        /// 메모리 잔존 공격 방지를 위한 명시적 소거를 위한 Drop 트레이트 구현입니다.
        impl Drop for $struct_name {
            fn drop(&mut self) {
                use core::ptr::write_volatile;
                for byte in self.i_key_pad.iter_mut() {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }
                for byte in self.o_key_pad.iter_mut() {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }
            }
        }
    };
}

impl_hmac_sha!(HMACSHA224, SHA224, SHA224_256_BLOCK_SIZE, 28);
impl_hmac_sha!(HMACSHA256, SHA256, SHA224_256_BLOCK_SIZE, 32);
impl_hmac_sha!(HMACSHA384, SHA384, SHA384_512_BLOCK_SIZE, 48);
impl_hmac_sha!(HMACSHA512, SHA512, SHA384_512_BLOCK_SIZE, 64);

impl_hmac_sha!(HMACSHA3_224, SHA3_224, SHA3_224_BLOCK_SIZE, 28);
impl_hmac_sha!(HMACSHA3_256, SHA3_256, SHA3_256_BLOCK_SIZE, 32);
impl_hmac_sha!(HMACSHA3_384, SHA3_384, SHA3_384_BLOCK_SIZE, 48);
impl_hmac_sha!(HMACSHA3_512, SHA3_512, SHA3_512_BLOCK_SIZE, 64);
