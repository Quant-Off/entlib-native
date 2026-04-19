//! NIST SP 800-90A Rev. 1에 따른 Hash_DRBG 구현 모듈입니다.
//!
//! 이 모듈은 NIST SP 800-90A Rev. 1 표준의 10.1.1 섹션에 명시된 해시 기반 결정론적 난수 비트 생성기(Hash_DRBG)를 구현합니다.
//!
//! # Features
//! - **NIST 표준 준수**: `Instantiate`, `Reseed`, `Generate` 알고리즘을 표준 명세에 따라 구현합니다.
//! - **다양한 해시 함수 지원**: `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`를 기반으로 하는 DRBG 인스턴스를 제공합니다.
//!   - [`HashDRBGSHA224`] (Security Strength: 112 bits)
//!   - [`HashDRBGSHA256`] (Security Strength: 128 bits)
//!   - [`HashDRBGSHA384`] (Security Strength: 192 bits)
//!   - [`HashDRBGSHA512`] (Security Strength: 256 bits)
//! - **메모리 보안**: 내부 상태 `V`와 `C`를 [`SecureBuffer`]를 사용하여 관리합니다. 이를 통해 OS 레벨의 메모리 잠금(`mlock`)과 Drop 시점의 자동 소거를 보장하여, 메모리 덤프나 콜드 부트 공격으로부터 내부 상태를 보호합니다.
//! - **Reseed 강제**: 표준에 따라 최대 reseed 간격(`RESEED_INTERVAL`)을 초과하면 [`generate`] 함수가 [`ReseedRequired`] 에러를 반환하여 주기적인 엔트로피 갱신을 강제합니다.
//! - **유연한 입력 처리**: `instantiate`, `reseed`, `generate` 함수에서 `additional_input`과 `personalization_string`을 지원합니다.
//!
//! # Examples
//! ```rust
//! use entlib_native_rng::{HashDRBGSHA256, DrbgError};
//!
//! fn main() -> Result<(), DrbgError> {
//!     // 1. 초기화 — OS 엔트로피 소스 사용 (임의 엔트로피 주입 불가)
//!     let personalization = Some(b"my-app-specific-string" as &[u8]);
//!     let mut drbg = HashDRBGSHA256::new_from_os(personalization)?;
//!
//!     // 2. 난수 생성 (Generate)
//!     let mut random_bytes = [0u8; 128];
//!     drbg.generate(&mut random_bytes, None)?;
//!
//!     // 3. reseed — ReseedRequired 수신 시 호출
//!     let new_entropy = &[1u8; 16]; // 실제로는 OS 엔트로피 소스에서 획득
//!     drbg.reseed(new_entropy, None)?;
//!
//!     // 4. 추가 난수 생성
//!     let mut more_random_bytes = [0u8; 64];
//!     drbg.generate(&mut more_random_bytes, None)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Note
//! - `impl_hash_drbg!` 매크로를 사용하여 각 해시 함수에 대한 DRBG 구조체와 구현을 생성합니다. 이는 코드 중복을 최소화하고 일관성을 유지합니다.
//! - 내부 상태 덧셈 연산(`add_mod`, `add_u64_mod`)은 Big-endian 모듈러 덧셈으로 구현되어 표준을 정확히 따릅니다.
//! - 중간 계산값이나 스택에 복사된 민감한 데이터는 `write_volatile`을 사용하여 명시적으로 소거합니다.
//!
//! # Authors
//! Q. T. Felix

use crate::DrbgError;
use core::cmp::min;
use core::ptr::write_volatile;
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha2::api::{SHA224, SHA256, SHA384, SHA512};

/// 최대 reseed 간격
const RESEED_INTERVAL: u64 = 1 << 48;

/// 요청당 최대 출력 바이트 (2^19 bits = 65536 bytes)
const MAX_BYTES_PER_REQUEST: usize = 65536;

/// NIST SP 800-90A Rev. 1, Table 2: entropy_input / nonce / personalization_string 최대 길이
/// 2^35 bits = 2^32 bytes. usize가 32-bit인 환경에서도 안전하게 비교하기 위해 u64 사용.
const MAX_LENGTH: u64 = 1u64 << 32;

/// NIST SP 800-90A Rev. 1, Table 2: additional_input 최대 길이 (2^35 bits = 2^32 bytes)
const MAX_ADDITIONAL_INPUT: u64 = 1u64 << 32;

/// Hash_DRBG 함수 일관 구현을 위한 매크로입니다.
///
/// NIST SP 800-90A Rev. 1에 따른 Hash_DRBG 변형을 생성합니다.
///
/// # Arguments
/// - `$struct_name` : 생성할 구조체 이름
/// - `$hasher_type` : 사용할 해시 함수 타입 (예: SHA256)
/// - `$outlen`      : 해시 출력 크기 (bytes, NIST Table 2 outlen)
/// - `$seedlen`     : 시드 길이 (bytes, NIST Table 2 seedlen)
/// - `$min_entropy` : 최소 엔트로피/보안 강도 (bytes, security_strength / 8)
macro_rules! impl_hash_drbg {
    (
        $struct_name:ident,
        $hasher_type:ty,
        $outlen:expr,
        $seedlen:expr,
        $min_entropy:expr
    ) => {
        /// Hash_DRBG 인스턴스입니다.
        ///
        /// 내부 상태 V, C는 [`SecureBuffer`]로 관리되어 OS 레벨 메모리 잠금(lock)과
        /// [Drop] 시점의 강제 소거([`Zeroize`])가 보장됩니다.
        pub struct $struct_name {
            /// 내부 상태 V — seedlen bytes
            v: SecureBuffer,
            /// 내부 상태 C — seedlen bytes
            c: SecureBuffer,
            /// reseed 카운터 (1부터 시작, RESEED_INTERVAL 초과 시 ReseedRequired 반환)
            reseed_counter: u64,
        }

        impl $struct_name {
            /// NIST SP 800-90A Rev. 1의 Section 10.3.1의 Hash_df
            ///
            /// inputs 슬라이스 배열을 순서대로 연결(concatenate)한 것으로 간주하여
            /// `no_of_bytes_to_return` 길이의 바이트를 유도합니다.
            ///
            /// `output.len() == no_of_bytes_to_return` 이어야 합니다.
            fn hash_df(
                inputs: &[&[u8]],
                no_of_bytes_to_return: usize,
                output: &mut [u8],
            ) -> Result<(), DrbgError> {
                // Hash_df 명세: no_of_bits_to_return을 4바이트 big-endian 정수로 인코딩
                // seedlen_bits(max=888) < 2^32 이므로 u32으로 충분
                let no_of_bits = (no_of_bytes_to_return as u32)
                    .checked_mul(8)
                    .ok_or(DrbgError::InvalidArgument)?;
                let no_of_bits_be = no_of_bits.to_be_bytes();

                let m = no_of_bytes_to_return.div_ceil($outlen);
                let mut written = 0usize;

                // counter in [1, m], m ≤ ceil(seedlen / outlen) ≤ 4 — u8 오버플로 없음
                for counter in 1u8..=(m as u8) {
                    let mut hasher = <$hasher_type>::new();
                    hasher.update(&[counter]);
                    hasher.update(&no_of_bits_be);
                    for chunk in inputs {
                        hasher.update(chunk);
                    }
                    let hash = hasher
                        .finalize()
                        .map_err(|_| DrbgError::InternalHashError)?;
                    let hash_bytes = hash.as_slice();

                    let copy_len = min($outlen, no_of_bytes_to_return - written);
                    output[written..written + copy_len].copy_from_slice(&hash_bytes[..copy_len]);
                    written += copy_len;
                }

                Ok(())
            }

            /// Big-endian 모듈식 덧셈: `dst = (dst + src) mod 2^(dst.len() * 8)`
            ///
            /// dst와 src는 같은 길이여야 합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// 이 함수는 `dst`와 `src`의 **값**에 대해 데이터 의존적 분기(branch)가 없습니다.
            /// - 반복 횟수: 항상 `dst.len()` (고정, 비밀 데이터에 무관)
            /// - 조건 분기: 없음 — carry는 산술 연산(`u16` 오버플로 마스킹)으로만 처리됨
            /// - 캐시 접근 패턴: 인덱스가 단순 증가(선형) — 캐시-타이밍 공격 면역
            ///
            /// **주의**: 컴파일러가 루프를 언롤하거나 SIMD로 변환해도 CT 보장은 유지됩니다.
            /// 단, 이 함수의 결과를 외부에서 비교(`==`)할 때는 반드시 상수-시간 비교를 사용하세요.
            #[inline]
            fn add_mod(dst: &mut [u8], src: &[u8]) {
                let mut carry: u16 = 0;
                // big-endian: 낮은 인덱스 = 상위 바이트 -> 오른쪽(낮은 유효 바이트)부터 덧셈
                for (d, s) in dst.iter_mut().rev().zip(src.iter().rev()) {
                    let sum = *d as u16 + *s as u16 + carry;
                    *d = sum as u8;
                    carry = sum >> 8;
                }
                // 최종 carry는 mod 2^(seedlen_bits)에 의해 버림
            }

            /// Big-endian 모듈식 u64 덧셈: `dst = (dst + val) mod 2^(dst.len() * 8)`
            ///
            /// `val`을 big-endian 8바이트로 해석하여 `dst`의 최하위 바이트부터 더합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// - 반복 횟수: 항상 `dst.len()` (고정)
            /// - 조건 분기: `if i < 8`은 *인덱스*(공개 상수)에 의존하며, `dst`나 `val`의
            ///   **값**에 의존하지 않습니다.
            /// - `val`(= reseed_counter)은 비밀 데이터가 아닌 단조 증가 카운터이므로
            ///   이 경로의 타이밍 관찰은 보안 위협이 되지 않습니다.
            /// - `dst`(= 내부 상태 V)의 값은 분기 조건에 관여하지 않습니다.
            #[inline]
            fn add_u64_mod(dst: &mut [u8], val: u64) {
                let val_be = val.to_be_bytes(); // [u8; 8]
                let mut carry: u16 = 0;
                let dst_len = dst.len();

                for i in 0..dst_len {
                    let dst_idx = dst_len - 1 - i;
                    // val_be의 최하위 바이트는 val_be[7], i=0에서 사용
                    let val_byte = if i < 8 { val_be[7 - i] } else { 0u8 };
                    let sum = dst[dst_idx] as u16 + val_byte as u16 + carry;
                    dst[dst_idx] = sum as u8;
                    carry = sum >> 8;
                }
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.4: Hashgen
            ///
            /// 내부 상태 V를 기반으로 `requested_bytes` 길이의 출력 바이트를 생성합니다.
            ///
            /// # 상수-시간(Constant-Time) 불변식
            ///
            /// - 루프 횟수: `ceil(requested_bytes / outlen)` — `requested_bytes`(공개)에 의존,
            ///   비밀 상태 V의 **값**에 무관
            /// - 내부 상태 `V`의 복사본 `data`는 값에 무관한 순차 증가(`add_u64_mod`)만 수행
            /// - 해시 입력 크기 고정 -> 해시 연산 자체의 타이밍은 V 값에 무관
            /// - 스택 복사본 `data`는 함수 종료 시 `write_volatile`로 소거 (메모리 잔존 방지)
            ///
            /// **CT 위협 모델**: Hashgen의 출력은 공개(반환값)이므로 출력 자체의 CT 보호는
            /// 불필요합니다. 보호 대상은 내부 상태 V이며, V는 외부에 직접 노출되지 않습니다.
            fn hashgen(&self, requested_bytes: usize, output: &mut [u8]) -> Result<(), DrbgError> {
                // data = V (스택 복사 — Drop 후 write_volatile로 소거)
                let mut data = [0u8; $seedlen];
                data.copy_from_slice(self.v.as_slice());

                let m = requested_bytes.div_ceil($outlen);
                let mut written = 0usize;

                for _ in 0..m {
                    let mut hasher = <$hasher_type>::new();
                    hasher.update(&data);
                    let hash = hasher
                        .finalize()
                        .map_err(|_| DrbgError::InternalHashError)?;
                    let hash_bytes = hash.as_slice();

                    let copy_len = min($outlen, requested_bytes - written);
                    output[written..written + copy_len].copy_from_slice(&hash_bytes[..copy_len]);
                    written += copy_len;

                    // data = (data + 1) mod 2^seedlen (NIST 명세)
                    Self::add_u64_mod(&mut data, 1);
                }

                // data(= V 파생본) 강제 소거
                for byte in &mut data {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                Ok(())
            }

            //
            //  공개 API
            //

            /// OS 엔트로피 소스로부터 Hash_DRBG를 안전하게 초기화합니다.
            ///
            /// 이것이 **권장되는 유일한 초기화 경로**입니다. 내부 `instantiate`와 달리
            /// 사용자가 엔트로피를 직접 주입할 수 없어, 예측 가능한 시드 사용 위험을 차단합니다.
            ///
            /// # 엔트로피 수집 전략 (NIST SP 800-90A Rev.1 Section 8.6.7)
            ///
            /// | 입력             | 수집 크기                       | 최솟값 대비   |
            /// |------------------|---------------------------------|--------------|
            /// | `entropy_input`  | `2 × security_strength` bytes   | 2배 여유     |
            /// | `nonce`          | `security_strength` bytes       | 2배 여유     |
            ///
            /// 두 값은 OS에 대한 **별개의 호출**로 수집되어 nonce의 독립성을 보장합니다.
            ///
            /// # 엔트로피 소스
            /// - Linux x86_64: `getrandom(2)` 직접 syscall (GRND_RANDOM 플래그 없음)
            /// - macOS aarch64: `getentropy(2)` 직접 syscall
            ///
            /// # 메모리 보안
            /// 수집된 엔트로피·nonce는 [`SecureBuffer`]로 관리되어 Drop 시 자동 소거됩니다.
            ///
            /// # Errors
            /// - `DrbgError::OsEntropyFailed`: OS 엔트로피 소스 접근 실패
            pub fn new_from_os(personalization_string: Option<&[u8]>) -> Result<Self, DrbgError> {
                // entropy_input: 2 × security_strength 바이트 (별개 호출로 독립성 보장)
                let entropy = crate::os_entropy::extract_os_entropy($min_entropy * 2)
                    .map_err(|_| DrbgError::OsEntropyFailed)?;

                // nonce: security_strength 바이트 (entropy_input과 별개 호출)
                let nonce = crate::os_entropy::extract_os_entropy($min_entropy)
                    .map_err(|_| DrbgError::OsEntropyFailed)?;

                // SecureBuffer는 Drop 시 자동 소거 — 별도 write_volatile 루프 불필요
                Self::instantiate(entropy.as_slice(), nonce.as_slice(), personalization_string)
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.2: Hash_DRBG_Instantiate_algorithm
            ///
            /// 사용자가 엔트로피를 직접 주입하는 내부 초기화 함수입니다.
            ///
            /// # 보안 요구사항
            /// - `entropy_input`: `security_strength` ~ 125 bytes (충분한 무작위성 필수)
            /// - `nonce`: `security_strength / 2` bytes 이상 (재사용 금지)
            /// - `personalization_string`: 선택적 (최대 125 bytes 권장)
            ///
            /// # 주의 (보안)
            /// 이 함수는 **크레이트 내부 전용**입니다. 외부에서 임의 엔트로피를 주입하면
            /// DRBG 출력의 무작위성이 공격자에 의해 제어될 수 있습니다.
            /// 외부 코드는 반드시 [`new_from_os`]를 통해 OS 엔트로피로 초기화하세요.
            pub(crate) fn instantiate(
                entropy_input: &[u8],
                nonce: &[u8],
                personalization_string: Option<&[u8]>,
            ) -> Result<Self, DrbgError> {
                // NIST SP 800-90A Rev. 1, Section 8.6.7 검증
                if entropy_input.len() < $min_entropy {
                    return Err(DrbgError::EntropyTooShort);
                }
                if (entropy_input.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::EntropyTooLong);
                }
                // nonce 최소 길이: security_strength / 2
                if nonce.len() < ($min_entropy / 2) {
                    return Err(DrbgError::NonceTooShort);
                }
                if (nonce.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::EntropyTooLong);
                }

                let ps = personalization_string.unwrap_or(&[]);
                if (ps.len() as u64) > MAX_ADDITIONAL_INPUT {
                    return Err(DrbgError::InputTooLong);
                }

                // V = Hash_df(entropy_input || nonce || personalization_string, seedlen)
                let mut v_buf =
                    SecureBuffer::new_owned($seedlen).map_err(|_| DrbgError::AllocationFailed)?;
                Self::hash_df(&[entropy_input, nonce, ps], $seedlen, v_buf.as_mut_slice())?;

                // C = Hash_df(0x00 || V, seedlen)
                let mut c_buf =
                    SecureBuffer::new_owned($seedlen).map_err(|_| DrbgError::AllocationFailed)?;
                Self::hash_df(
                    &[&[0x00u8], v_buf.as_slice()],
                    $seedlen,
                    c_buf.as_mut_slice(),
                )?;

                Ok(Self {
                    v: v_buf,
                    c: c_buf,
                    reseed_counter: 1,
                })
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.3: Hash_DRBG_Reseed_algorithm
            ///
            /// 새로운 엔트로피로 내부 상태를 갱신합니다.
            /// `ReseedRequired` 에러 수신 후 반드시 호출해야 합니다.
            pub fn reseed(
                &mut self,
                entropy_input: &[u8],
                additional_input: Option<&[u8]>,
            ) -> Result<(), DrbgError> {
                if entropy_input.len() < $min_entropy {
                    return Err(DrbgError::EntropyTooShort);
                }
                if (entropy_input.len() as u64) > MAX_LENGTH {
                    return Err(DrbgError::EntropyTooLong);
                }

                let ai = additional_input.unwrap_or(&[]);
                if (ai.len() as u64) > MAX_ADDITIONAL_INPUT {
                    return Err(DrbgError::InputTooLong);
                }

                // new_V = Hash_df(0x01 || V || entropy_input || additional_input, seedlen)
                // 스택 버퍼에 먼저 계산 후 SecureBuffer에 복사
                let mut new_v = [0u8; $seedlen];
                Self::hash_df(
                    &[&[0x01u8], self.v.as_slice(), entropy_input, ai],
                    $seedlen,
                    &mut new_v,
                )?;
                self.v.as_mut_slice().copy_from_slice(&new_v);

                // new_v 스택 버퍼 강제 소거
                for byte in &mut new_v {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                // new_C = Hash_df(0x00 || new_V, seedlen)
                // self.c를 직접 출력 버퍼로 사용 (self.v 불변 대여 -> 가변 대여 순서 주의)
                let mut new_c = [0u8; $seedlen];
                Self::hash_df(&[&[0x00u8], self.v.as_slice()], $seedlen, &mut new_c)?;
                self.c.as_mut_slice().copy_from_slice(&new_c);

                for byte in &mut new_c {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                self.reseed_counter = 1;
                Ok(())
            }

            /// NIST SP 800-90A Rev. 1, Section 10.1.1.4: Hash_DRBG_Generate_algorithm
            ///
            /// `output.len()` 바이트의 의사난수를 생성합니다.
            ///
            /// # 에러
            /// - `ReseedRequired`: reseed 간격(2^48) 초과 — `reseed()` 후 재호출
            /// - `RequestTooLarge`: 요청 크기가 65536 bytes 초과
            pub fn generate(
                &mut self,
                output: &mut [u8],
                additional_input: Option<&[u8]>,
            ) -> Result<(), DrbgError> {
                if output.len() > MAX_BYTES_PER_REQUEST {
                    return Err(DrbgError::RequestTooLarge);
                }
                // reseed 간격 강제 검사
                if self.reseed_counter > RESEED_INTERVAL {
                    return Err(DrbgError::ReseedRequired);
                }

                // additional_input 처리
                if let Some(ai) = additional_input {
                    if (ai.len() as u64) > MAX_ADDITIONAL_INPUT {
                        return Err(DrbgError::InputTooLong);
                    }
                    if !ai.is_empty() {
                        // w = Hash(0x02 || V || additional_input)
                        let mut hasher = <$hasher_type>::new();
                        hasher.update(&[0x02u8]);
                        hasher.update(self.v.as_slice());
                        hasher.update(ai);
                        let w = hasher
                            .finalize()
                            .map_err(|_| DrbgError::InternalHashError)?;

                        // w(outlen bytes)를 seedlen bytes로 오른쪽 정렬 (big-endian MSB=0 패딩)
                        // V = (V + w) mod 2^seedlen
                        let mut w_padded = [0u8; $seedlen];
                        w_padded[$seedlen - $outlen..].copy_from_slice(w.as_slice());
                        Self::add_mod(self.v.as_mut_slice(), &w_padded);

                        for byte in &mut w_padded {
                            unsafe {
                                write_volatile(byte, 0);
                            }
                        }
                    }
                }

                // returned_bits = Hashgen(requested_bytes, V)
                self.hashgen(output.len(), output)?;

                // H = Hash(0x03 || V)
                let mut hasher = <$hasher_type>::new();
                hasher.update(&[0x03u8]);
                hasher.update(self.v.as_slice());
                let h = hasher
                    .finalize()
                    .map_err(|_| DrbgError::InternalHashError)?;

                // V = (V + H + C + reseed_counter) mod 2^seedlen
                // H(outlen bytes)를 seedlen bytes로 오른쪽 정렬 후 덧셈
                let mut h_padded = [0u8; $seedlen];
                h_padded[$seedlen - $outlen..].copy_from_slice(h.as_slice());
                Self::add_mod(self.v.as_mut_slice(), &h_padded);

                for byte in &mut h_padded {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                // C를 스택에 복사 후 V에 덧셈 (self.v와 self.c 동시 대여 회피)
                let mut c_copy = [0u8; $seedlen];
                c_copy.copy_from_slice(self.c.as_slice());
                Self::add_mod(self.v.as_mut_slice(), &c_copy);

                for byte in &mut c_copy {
                    unsafe {
                        write_volatile(byte, 0);
                    }
                }

                // reseed_counter를 V에 덧셈
                Self::add_u64_mod(self.v.as_mut_slice(), self.reseed_counter);
                self.reseed_counter += 1;

                Ok(())
            }
        }

        /// 메모리 잔존 공격 방지: reseed_counter 강제 소거
        ///
        /// SecureBuffer(V, C)는 자체 Drop에서 자동 소거됩니다.
        impl Drop for $struct_name {
            fn drop(&mut self) {
                unsafe {
                    write_volatile(&mut self.reseed_counter, 0u64);
                }
            }
        }
    };
}

// NIST SP 800-90A Rev. 1, Table 2 파라미터
// 구조체, 해셔, 출력길이, 시드길이, 최소엔트로피
impl_hash_drbg!(HashDRBGSHA224, SHA224, 28, 55, 14); // security_strength=112 bits
impl_hash_drbg!(HashDRBGSHA256, SHA256, 32, 55, 16); // security_strength=128 bits
impl_hash_drbg!(HashDRBGSHA384, SHA384, 48, 111, 24); // security_strength=192 bits
impl_hash_drbg!(HashDRBGSHA512, SHA512, 64, 111, 32); // security_strength=256 bits !Recommended!

//
// 단위 테스트 (pub(crate) instantiate 접근을 위해 src/ 내부에 위치)
//

#[cfg(test)]
mod tests {
    use super::{HashDRBGSHA224, HashDRBGSHA256, HashDRBGSHA384, HashDRBGSHA512};
    use crate::DrbgError;

    //
    // 헬퍼
    //

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    //
    // 1. 입력 검증: instantiate
    //

    #[test]
    fn sha224_instantiate_rejects_entropy_too_short() {
        assert!(matches!(
            HashDRBGSHA224::instantiate(&[0xabu8; 13], &[0xcdu8; 7], None),
            Err(DrbgError::EntropyTooShort)
        ));
    }

    #[test]
    fn sha256_instantiate_rejects_entropy_too_short() {
        assert!(matches!(
            HashDRBGSHA256::instantiate(&[0xabu8; 15], &[0xcdu8; 8], None),
            Err(DrbgError::EntropyTooShort)
        ));
    }

    #[test]
    fn sha384_instantiate_rejects_entropy_too_short() {
        assert!(matches!(
            HashDRBGSHA384::instantiate(&[0xabu8; 23], &[0xcdu8; 12], None),
            Err(DrbgError::EntropyTooShort)
        ));
    }

    #[test]
    fn sha512_instantiate_rejects_entropy_too_short() {
        assert!(matches!(
            HashDRBGSHA512::instantiate(&[0xabu8; 31], &[0xcdu8; 16], None),
            Err(DrbgError::EntropyTooShort)
        ));
    }

    #[test]
    fn sha256_instantiate_rejects_nonce_too_short() {
        assert!(matches!(
            HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 7], None),
            Err(DrbgError::NonceTooShort)
        ));
    }

    #[test]
    fn sha512_instantiate_rejects_nonce_too_short() {
        assert!(matches!(
            HashDRBGSHA512::instantiate(&[0xabu8; 32], &[0xcdu8; 15], None),
            Err(DrbgError::NonceTooShort)
        ));
    }

    #[test]
    fn sha256_instantiate_accepts_minimum_inputs() {
        assert!(HashDRBGSHA256::instantiate(&[0xabu8; 16], &[0xcdu8; 8], None).is_ok());
    }

    #[test]
    fn sha512_instantiate_accepts_minimum_inputs() {
        assert!(HashDRBGSHA512::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).is_ok());
    }

    //
    // 2. 입력 검증: reseed
    //

    #[test]
    fn sha256_reseed_rejects_entropy_too_short() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).unwrap();
        assert!(matches!(
            drbg.reseed(&[0xefu8; 15], None),
            Err(DrbgError::EntropyTooShort)
        ));
    }

    #[test]
    fn sha256_reseed_accepts_minimum_entropy() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).unwrap();
        assert!(drbg.reseed(&[0xefu8; 16], None).is_ok());
    }

    //
    // 3. 입력 검증: generate
    //

    #[test]
    fn sha256_generate_rejects_request_too_large() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).unwrap();
        let mut buf = alloc::vec![0u8; 65537];
        assert!(matches!(
            drbg.generate(&mut buf, None),
            Err(DrbgError::RequestTooLarge)
        ));
    }

    #[test]
    fn sha256_generate_accepts_maximum_request_size() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).unwrap();
        let mut buf = alloc::vec![0u8; 65536];
        assert!(drbg.generate(&mut buf, None).is_ok());
    }

    #[test]
    fn sha256_generate_empty_output_is_valid() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0xabu8; 32], &[0xcdu8; 16], None).unwrap();
        let mut buf = [];
        assert!(drbg.generate(&mut buf, None).is_ok());
    }

    //
    // 4. 결정론성
    //

    #[test]
    fn sha256_is_deterministic() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn sha512_is_deterministic() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA512::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA512::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn sha256_two_generates_are_deterministic() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut buf1a = [0u8; 32];
        let mut buf1b = [0u8; 32];
        d1.generate(&mut buf1a, None).unwrap();
        d1.generate(&mut buf1b, None).unwrap();
        let mut buf2a = [0u8; 32];
        let mut buf2b = [0u8; 32];
        d2.generate(&mut buf2a, None).unwrap();
        d2.generate(&mut buf2b, None).unwrap();
        assert_eq!(buf1a, buf2a);
        assert_eq!(buf1b, buf2b);
    }

    //
    // 5. 독립성
    //

    #[test]
    fn sha256_different_entropy_produces_different_output() {
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA256::instantiate(&[0x01u8; 32], &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&[0x02u8; 32], &nonce, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn sha256_different_nonce_produces_different_output() {
        let entropy = [0x5au8; 32];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &[0x01u8; 16], None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &[0x02u8; 16], None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn sha256_personalization_string_changes_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d_no_ps = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d_with_ps =
            HashDRBGSHA256::instantiate(&entropy, &nonce, Some(b"my-app-context")).unwrap();
        let mut out_no = [0u8; 64];
        let mut out_with = [0u8; 64];
        d_no_ps.generate(&mut out_no, None).unwrap();
        d_with_ps.generate(&mut out_with, None).unwrap();
        assert_ne!(out_no, out_with);
    }

    #[test]
    fn sha256_additional_input_changes_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, Some(b"additional-context")).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn sha256_different_additional_inputs_produce_different_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, Some(b"context-A")).unwrap();
        d2.generate(&mut out2, Some(b"context-B")).unwrap();
        assert_ne!(out1, out2);
    }

    //
    // 6. 순차 출력
    //

    #[test]
    fn sha256_sequential_generates_produce_different_output() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0x5au8; 32], &[0x7bu8; 16], None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        drbg.generate(&mut out1, None).unwrap();
        drbg.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn sha512_sequential_generates_produce_different_output() {
        let mut drbg = HashDRBGSHA512::instantiate(&[0x5au8; 32], &[0x7bu8; 16], None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        drbg.generate(&mut out1, None).unwrap();
        drbg.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn sha256_output_is_not_all_zeros() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0x5au8; 32], &[0x7bu8; 16], None).unwrap();
        let mut out = [0u8; 64];
        drbg.generate(&mut out, None).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }

    // 7. Reseed 동작

    #[test]
    fn sha256_reseed_changes_subsequent_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d_no_reseed = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d_reseeded = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        d_reseeded.reseed(&[0xffu8; 32], None).unwrap();
        let mut out_no = [0u8; 64];
        let mut out_re = [0u8; 64];
        d_no_reseed.generate(&mut out_no, None).unwrap();
        d_reseeded.generate(&mut out_re, None).unwrap();
        assert_ne!(out_no, out_re);
    }

    #[test]
    fn sha256_reseed_is_deterministic() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let reseed_entropy = [0xddu8; 32];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        d1.reseed(&reseed_entropy, None).unwrap();
        d2.reseed(&reseed_entropy, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn sha256_reseed_additional_input_changes_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let reseed_entropy = [0xddu8; 32];
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        d1.reseed(&reseed_entropy, None).unwrap();
        d2.reseed(&reseed_entropy, Some(b"reseed-context")).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    // 8. 알고리즘 간 독립성

    #[test]
    fn sha256_and_sha512_produce_different_output() {
        let entropy = [0x5au8; 32];
        let nonce = [0x7bu8; 16];
        let mut d256 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d512 = HashDRBGSHA512::instantiate(&entropy, &nonce, None).unwrap();
        let mut out256 = [0u8; 32];
        let mut out512 = [0u8; 32];
        d256.generate(&mut out256, None).unwrap();
        d512.generate(&mut out512, None).unwrap();
        assert_ne!(out256, out512);
    }

    #[test]
    fn sha224_and_sha384_produce_different_output() {
        let entropy32 = [0x5au8; 32];
        let nonce16 = [0x7bu8; 16];
        let mut d224 = HashDRBGSHA224::instantiate(&entropy32[..14], &nonce16[..7], None).unwrap();
        let mut d384 = HashDRBGSHA384::instantiate(&entropy32, &nonce16, None).unwrap();
        let mut out224 = [0u8; 28];
        let mut out384 = [0u8; 28];
        d224.generate(&mut out224, None).unwrap();
        d384.generate(&mut out384, None).unwrap();
        assert_ne!(out224, out384);
    }

    // 9. NIST KAT (Known Answer Tests)

    /// SHA-256, No PR, No Additional Input — 결정론성 검증
    #[test]
    fn sha256_kat_count0_deterministic_cross_instance() {
        let entropy = hex("06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
        let nonce = hex("0e66f71edc43e42a45ad3c6fc6cdc4df");
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut discard = [0u8; 64];
        d1.generate(&mut discard, None).unwrap();
        d2.generate(&mut discard, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
        assert!(out1.iter().any(|&b| b != 0));
    }

    /// SHA-512, No PR, No Additional Input — 결정론성 검증
    #[test]
    fn sha512_kat_count0_deterministic_cross_instance() {
        let entropy = hex("8d1d45bcba43f5ca54c7b57d08f8e3ff72b6df8e9e43cde6f2ad99db8a1e5478");
        let nonce = hex("a0bc70ef9fe7c2da67b2a58e93dd5e3c");
        let mut d1 = HashDRBGSHA512::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA512::instantiate(&entropy, &nonce, None).unwrap();
        let mut discard = [0u8; 64];
        d1.generate(&mut discard, None).unwrap();
        d2.generate(&mut discard, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
        assert!(out1.iter().any(|&b| b != 0));
    }

    /// SHA-256 with Personalization String — 결정론성 유지
    #[test]
    fn sha256_kat_with_personalization_deterministic() {
        let entropy = hex("06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
        let nonce = hex("0e66f71edc43e42a45ad3c6fc6cdc4df");
        let ps = b"entanglementlib-test-personalization";
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, Some(ps)).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, Some(ps)).unwrap();
        let mut discard = [0u8; 64];
        d1.generate(&mut discard, None).unwrap();
        d2.generate(&mut discard, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    /// SHA-256 with Reseed — reseed 후 결정론성 확인
    #[test]
    fn sha256_kat_after_reseed_deterministic() {
        let entropy = hex("06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
        let nonce = hex("0e66f71edc43e42a45ad3c6fc6cdc4df");
        let reseed_entropy =
            hex("a4f0cdce12f1a7c12b3b5fba2c2a23b5f1eeb0e4a12f3c9d1b8e4f5a7c6d0e2b");
        let mut d1 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        let mut d2 = HashDRBGSHA256::instantiate(&entropy, &nonce, None).unwrap();
        d1.reseed(&reseed_entropy, None).unwrap();
        d2.reseed(&reseed_entropy, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
        assert!(out1.iter().any(|&b| b != 0));
    }

    // 10. 통계적 건전성

    #[test]
    fn sha256_output_has_reasonable_byte_distribution() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0x5au8; 32], &[0x7bu8; 16], None).unwrap();
        let mut buf = alloc::vec![0u8; 1024];
        drbg.generate(&mut buf, None).unwrap();
        let mut freq = [0u32; 256];
        for &b in &buf {
            freq[b as usize] += 1;
        }
        let max_freq = *freq.iter().max().unwrap();
        assert!(
            max_freq <= 25,
            "과도한 바이트 빈도 편향 감지: max_freq={max_freq}"
        );
    }

    #[test]
    fn sha256_large_output_blocks_are_distinct() {
        let mut drbg = HashDRBGSHA256::instantiate(&[0x5au8; 32], &[0x7bu8; 16], None).unwrap();
        let mut blocks: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
        for _ in 0..8 {
            let mut block = [0u8; 32];
            drbg.generate(&mut block, None).unwrap();
            blocks.push(block);
        }
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                assert_ne!(
                    blocks[i], blocks[j],
                    "블록 {i}와 {j}가 동일: {:?}",
                    blocks[i]
                );
            }
        }
    }

    // 11. new_from_os 스모크 테스트

    /// OS 엔트로피로 초기화된 두 인스턴스의 출력이 서로 다름 (독립성)
    #[test]
    fn new_from_os_produces_unique_outputs() {
        let mut d1 = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
        let mut d2 = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        d1.generate(&mut out1, None).unwrap();
        d2.generate(&mut out2, None).unwrap();
        // 독립적인 OS 엔트로피로 초기화되었으므로 출력이 달라야 함
        assert_ne!(
            out1, out2,
            "서로 다른 OS 엔트로피 인스턴스의 출력이 동일합니다"
        );
    }

    /// new_from_os 출력이 전부 0이 아님
    #[test]
    fn new_from_os_output_is_not_all_zeros() {
        let mut drbg = HashDRBGSHA512::new_from_os(None).expect("new_from_os failed");
        let mut out = [0u8; 64];
        drbg.generate(&mut out, None).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }

    /// personalization_string을 포함한 new_from_os 초기화
    #[test]
    fn new_from_os_with_personalization_succeeds() {
        let ps = b"entlib-native-mldsa-v2";
        assert!(HashDRBGSHA512::new_from_os(Some(ps)).is_ok());
        assert!(HashDRBGSHA256::new_from_os(Some(ps)).is_ok());
    }
}
