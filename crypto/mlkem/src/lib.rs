//! FIPS 203 명세에 따른 모듈 격자 기반 키 캡슐화 메커니즘(Module Lattice-based
//! Key-Encapsulation Mechanism, ML-KEM) 알고리즘 구현 모듈입니다.
//! 해당 명세 KEM 스키마의 최상위 공개 인터페이스를 제공합니다.
//!
//! # Examples
//! ```rust,ignore
//! use entlib_native_mlkem::{MLKEM, MLKEMParameter, HashDRBGRng};
//!
//! // 1. RNG 초기화 (OS 엔트로피 소스 사용)
//! let mut rng = HashDRBGRng::new_from_os(None).unwrap();
//!
//! // 2. 키 쌍 생성 (ML-KEM-768)
//! let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM768, &mut rng).unwrap();
//!
//! // 3. 캡슐화 (공유 비밀 + 암호문 생성)
//! let (shared_secret, ciphertext) = MLKEM::encaps(&ek, &mut rng).unwrap();
//!
//! // 4. 역캡슐화 (공유 비밀 복원)
//! let decapsulated = MLKEM::decaps(&dk, &ciphertext).unwrap();
//! assert_eq!(shared_secret.as_slice(), decapsulated.as_slice());
//! ```

mod encode;
mod error;
mod field;
mod k_pke;
mod ntt;
mod poly;
mod sample;

use entlib_native_constant_time::choice::Choice;
use entlib_native_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use entlib_native_rng::{DrbgError, HashDRBGSHA512};
use entlib_native_secure_buffer::SecureBuffer;

use crate::encode::byte_decode;
use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_keygen, sha3_256, sha3_512, shake256_32};

pub use error::MLKEMError;

//
// ML-KEM-512 크기 상수
//

const MLKEM512_EK_LEN: usize = 800;
const MLKEM512_DK_LEN: usize = 1632;
const MLKEM512_CT_LEN: usize = 768;

//
// ML-KEM-768 크기 상수
//

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_DK_LEN: usize = 2400;
const MLKEM768_CT_LEN: usize = 1088;

//
// ML-KEM-1024 크기 상수
//

const MLKEM1024_EK_LEN: usize = 1568;
const MLKEM1024_DK_LEN: usize = 3168;
const MLKEM1024_CT_LEN: usize = 1568;

//
// RNG 추상화 트레이트
//

/// ML-KEM 연산에 사용되는 암호학적으로 안전한 난수 생성기 트레이트.
///
/// 이 트레이트를 구현하는 타입은 NIST SP 800-90A Rev.1 이상의 보안 강도를
/// 제공하는 결정론적 난수 비트 생성기(DRBG)여야 합니다.
///
/// # Features
/// - [`HashDRBGRng`]: NIST Hash_DRBG (SHA-512, Security Strength 256-bit)
/// - [`CtrDRBGRng`]: NIST CTR_DRBG (AES-256-CTR) **향후 개발 예정**
pub trait MLKEMRng {
    /// `dest` 슬라이스를 암호학적으로 안전한 난수 바이트로 채웁니다.
    ///
    /// # Errors
    /// - `MLKEMError::RngError`: RNG 내부 오류 또는 reseed가 필요한 경우
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLKEMError>;
}

//
// Hash_DRBG 래퍼
//

/// NIST SP 800-90A Rev.1 Hash_DRBG (SHA-512 기반) RNG 래퍼.
///
/// ML-KEM 키 생성 및 캡슐화에 사용하도록 설계되었습니다.
/// - Security Strength: **256-bit**
/// - 최소 엔트로피: 32바이트
/// - 최소 Nonce: 16바이트
/// - 내부 상태(V, C)는 [`SecureBuffer`]에 보관되어 Drop 시 자동 소거됩니다.
///
/// # Security Note
/// `entropy_input`은 반드시 `/dev/urandom`, HWRNG, 또는 동등한 암호학적
/// 엔트로피 소스에서 획득해야 합니다. 예측 가능한 값을 절대 사용하지 마세요.
pub struct HashDRBGRng {
    inner: HashDRBGSHA512,
}

impl HashDRBGRng {
    /// OS 엔트로피 소스로부터 Hash_DRBG(SHA-512)를 초기화합니다.
    ///
    /// 이것이 유일한 초기화 경로입니다. 외부에서 임의 엔트로피를 주입할 수 없으며,
    /// OS(Linux: `getrandom(2)`, macOS: `getentropy(2)`)가 수집한 엔트로피만 사용됩니다.
    ///
    /// # Arguments
    /// - `personalization_string`: 선택적 응용 프로그램 식별 문자열 (최대 125 bytes)
    ///
    /// # Errors
    /// - `MLKEMError::RngError`: OS 엔트로피 소스 접근 실패 또는 내부 오류
    pub fn new_from_os(personalization_string: Option<&[u8]>) -> Result<Self, MLKEMError> {
        let inner = HashDRBGSHA512::new_from_os(personalization_string).map_err(drbg_err)?;
        Ok(Self { inner })
    }

    /// 현재 RNG 상태를 새 엔트로피로 갱신합니다.
    ///
    /// `MLKEMError::RngError(ReseedRequired)`를 수신한 경우 반드시 호출해야 합니다.
    pub fn reseed(
        &mut self,
        entropy_input: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), MLKEMError> {
        self.inner
            .reseed(entropy_input, additional_input)
            .map_err(drbg_err)
    }
}

impl MLKEMRng for HashDRBGRng {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLKEMError> {
        self.inner.generate(dest, None).map_err(drbg_err)
    }
}

//
// CTR_DRBG 래퍼 (미구현 — 확장 예약)
//

/// NIST SP 800-90A Rev.1 CTR_DRBG (AES-256-CTR 기반) RNG 래퍼.
///
/// AES-256-CTR 구현이 준비되면 이 구조체에 내부 상태를 추가하고
/// [`MLKEMRng`] impl 내에서 CTR_DRBG 알고리즘을 구현합니다.
///
/// # Security Note
/// **현재 미구현 상태입니다.**
/// AES-256 블록 암호 구현 크레이트(`entlib-native-aes`) 완료 후 제공될 예정입니다.
pub struct CtrDRBGRng {
    _private: (),
}

impl CtrDRBGRng {
    /// CTR_DRBG를 초기화합니다.
    ///
    /// **현재 항상 `MLKEMError::NotImplemented`를 반환합니다.**
    pub fn new(_entropy_input: &[u8], _nonce: &[u8]) -> Result<Self, MLKEMError> {
        Err(MLKEMError::NotImplemented(
            "CTR_DRBG: AES-256 구현 완료 후 제공됩니다",
        ))
    }
}

impl MLKEMRng for CtrDRBGRng {
    fn fill_random(&mut self, _dest: &mut [u8]) -> Result<(), MLKEMError> {
        Err(MLKEMError::NotImplemented(
            "CTR_DRBG: AES-256 구현 완료 후 제공됩니다",
        ))
    }
}

//
// ML-KEM 파라미터 셋
//

/// NIST FIPS 203에 정의된 ML-KEM 파라미터 셋
///
/// | 파라미터 셋    | NIST 카테고리      | ek 크기  | dk 크기  | 암호문 크기 |
/// |---------------|:------------------:|--------:|--------:|-----------:|
/// | MLKEM512      | 1 (AES-128 동급)   |  800 B  | 1632 B  |    768 B   |
/// | MLKEM768      | 3 (AES-192 동급)   | 1184 B  | 2400 B  |   1088 B   |
/// | MLKEM1024     | 5 (AES-256 동급)   | 1568 B  | 3168 B  |   1568 B   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MLKEMParameter {
    /// ML-KEM-512: NIST 보안 카테고리 1 (Security Strength ≥ 128-bit)
    MLKEM512,
    /// ML-KEM-768: NIST 보안 카테고리 3 (Security Strength ≥ 192-bit)
    MLKEM768,
    /// ML-KEM-1024: NIST 보안 카테고리 5 (Security Strength ≥ 256-bit)
    MLKEM1024,
}

impl MLKEMParameter {
    /// 캡슐화 키 바이트 길이를 반환합니다.
    #[inline]
    pub const fn ek_len(self) -> usize {
        match self {
            MLKEMParameter::MLKEM512 => MLKEM512_EK_LEN,
            MLKEMParameter::MLKEM768 => MLKEM768_EK_LEN,
            MLKEMParameter::MLKEM1024 => MLKEM1024_EK_LEN,
        }
    }

    /// 역캡슐화 키 바이트 길이를 반환합니다.
    #[inline]
    pub const fn dk_len(self) -> usize {
        match self {
            MLKEMParameter::MLKEM512 => MLKEM512_DK_LEN,
            MLKEMParameter::MLKEM768 => MLKEM768_DK_LEN,
            MLKEMParameter::MLKEM1024 => MLKEM1024_DK_LEN,
        }
    }

    /// 암호문 바이트 길이를 반환합니다.
    #[inline]
    pub const fn ct_len(self) -> usize {
        match self {
            MLKEMParameter::MLKEM512 => MLKEM512_CT_LEN,
            MLKEMParameter::MLKEM768 => MLKEM768_CT_LEN,
            MLKEMParameter::MLKEM1024 => MLKEM1024_CT_LEN,
        }
    }

    /// 모듈 차원 k를 반환합니다.
    #[inline]
    const fn k(self) -> usize {
        match self {
            MLKEMParameter::MLKEM512 => 2,
            MLKEMParameter::MLKEM768 => 3,
            MLKEMParameter::MLKEM1024 => 4,
        }
    }
}

//
// 캡슐화 키 타입
//

/// ML-KEM 캡슐화 키 (공개 키).
///
/// 인코딩된 캡슐화 키 바이트(`ByteEncode_12(t_hat) || ρ`)와 파라미터 셋을 함께 보유합니다.
/// [`MLKEM::key_gen`]이 반환하며, [`MLKEM::encaps`]에 직접 전달할 수 있습니다.
pub struct MLKEMEncapsulationKey {
    param: MLKEMParameter,
    bytes: Vec<u8>,
}

impl MLKEMEncapsulationKey {
    /// 이 캡슐화 키가 속한 파라미터 셋을 반환합니다.
    #[inline]
    pub fn param(&self) -> MLKEMParameter {
        self.param
    }

    /// 인코딩된 캡슐화 키 바이트 슬라이스를 반환합니다.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 인코딩된 캡슐화 키의 바이트 길이를 반환합니다.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// 캡슐화 키가 비어 있으면 `true`를 반환합니다.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 인코딩된 바이트열로부터 캡슐화 키를 복원합니다.
    ///
    /// FIPS 203 모듈러스 검사를 수행합니다: 모든 12-bit 계수가 q 미만인지 확인합니다.
    ///
    /// # Errors
    /// - `InvalidLength`: 바이트 길이가 파라미터 셋과 불일치
    /// - `InvalidEncapsulationKey`: 모듈러스 검사 실패
    pub fn from_bytes(param: MLKEMParameter, bytes: Vec<u8>) -> Result<Self, MLKEMError> {
        if bytes.len() != param.ek_len() {
            return Err(MLKEMError::InvalidLength("캡슐화 키 길이 불일치"));
        }
        if !validate_ek_coefficients(&bytes, param.k()) {
            return Err(MLKEMError::InvalidEncapsulationKey);
        }
        Ok(Self { param, bytes })
    }
}

//
// 역캡슐화 키 타입
//

/// ML-KEM 역캡슐화 키 (비밀 키).
///
/// 직렬화된 역캡슐화 키 바이트를 OS 레벨 잠금 메모리([`SecureBuffer`])에 보관합니다.
/// `Drop` 시점에 메모리가 자동으로 소거(Zeroize)됩니다.
///
/// [`MLKEM::key_gen`]이 반환하며, [`MLKEM::decaps`]에 직접 전달할 수 있습니다.
pub struct MLKEMDecapsulationKey {
    param: MLKEMParameter,
    dk_buf: SecureBuffer,
}

impl MLKEMDecapsulationKey {
    /// 이 역캡슐화 키가 속한 파라미터 셋을 반환합니다.
    #[inline]
    pub fn param(&self) -> MLKEMParameter {
        self.param
    }

    /// 인코딩된 역캡슐화 키의 바이트 길이를 반환합니다.
    #[inline]
    pub fn len(&self) -> usize {
        self.dk_buf.len()
    }

    /// 역캡슐화 키가 비어 있으면 `true`를 반환합니다.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.dk_buf.is_empty()
    }

    /// 인코딩된 역캡슐화 키 바이트 슬라이스를 반환합니다.
    ///
    /// # Security Note
    /// 반환된 슬라이스는 잠금 메모리(mlock)에 보관된 민감 데이터입니다.
    /// 파일 저장 시 반드시 PKCS#8 암호화를 적용하십시오.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.dk_buf.as_slice()
    }

    /// 인코딩된 바이트열로부터 역캡슐화 키를 복원합니다.
    ///
    /// FIPS 203 해시 검증을 수행합니다: `H(ek) == dk[768k+32..768k+64]`.
    ///
    /// # Security Note
    /// `bytes`는 호출 즉시 SecureBuffer(mlock)로 이전됩니다.
    ///
    /// # Errors
    /// - `InvalidLength`: 바이트 길이가 파라미터 셋과 불일치
    /// - `InvalidDecapsulationKey`: 해시 검증 실패
    pub fn from_bytes(param: MLKEMParameter, bytes: &[u8]) -> Result<Self, MLKEMError> {
        if bytes.len() != param.dk_len() {
            return Err(MLKEMError::InvalidLength("역캡슐화 키 길이 불일치"));
        }
        let k = param.k();
        let embedded_ek = &bytes[384 * k..768 * k + 32];
        let embedded_h = &bytes[768 * k + 32..768 * k + 64];
        let computed_h = sha3_256(embedded_ek)?;
        if embedded_h != computed_h.as_slice() {
            return Err(MLKEMError::InvalidDecapsulationKey);
        }
        let mut dk_buf = SecureBuffer::new_owned(bytes.len())
            .map_err(|_| MLKEMError::InternalError("SecureBuffer 할당 실패"))?;
        dk_buf.as_mut_slice().copy_from_slice(bytes);
        Ok(Self { param, dk_buf })
    }
}

//
// MLKEM 공개 API
//

/// NIST FIPS 203 ML-KEM 키 캡슐화 메커니즘의 최상위 진입점.
///
/// 모든 메소드는 정적(static)이며, 파라미터 셋 정보는 키 타입에 내장됩니다.
pub struct MLKEM;

impl MLKEM {
    //
    // 외부 인터페이스 (FIPS 203 Algorithms 19–21)
    //

    /// Algorithm 19: ML-KEM.KeyGen()
    ///
    /// RNG로 32바이트 시드 d와 z를 생성하고, 이를 바탕으로 캡슐화 키와
    /// 역캡슐화 키 쌍을 결정론적으로 유도합니다.
    ///
    /// # Returns
    /// - [`MLKEMEncapsulationKey`]: 파라미터 셋과 인코딩된 캡슐화 키 바이트를 보유
    /// - [`MLKEMDecapsulationKey`]: 역캡슐화 키를 OS 잠금 메모리에 보관 (Drop 시 자동 소거)
    ///
    /// # Errors
    /// - `MLKEMError::RngError`: RNG에서 시드를 얻지 못한 경우
    /// - `MLKEMError::InternalError`: 내부 연산 실패
    pub fn key_gen<R: MLKEMRng>(
        param: MLKEMParameter,
        rng: &mut R,
    ) -> Result<(MLKEMEncapsulationKey, MLKEMDecapsulationKey), MLKEMError> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill_random(&mut d)?;
        rng.fill_random(&mut z)?;

        let (ek_bytes, dk_buf) = Self::key_gen_internal(param, &d, &z)?;
        Ok((
            MLKEMEncapsulationKey {
                param,
                bytes: ek_bytes,
            },
            MLKEMDecapsulationKey { param, dk_buf },
        ))
    }

    /// Algorithm 20: ML-KEM.Encaps(ek)
    ///
    /// 캡슐화 키 `ek`를 이용하여 공유 비밀 키 K와 암호문 c를 생성합니다.
    ///
    /// # Arguments
    /// - `ek`: [`key_gen`](Self::key_gen)이 반환한 [`MLKEMEncapsulationKey`]
    /// - `rng`: 캡슐화에 사용할 RNG
    ///
    /// # Returns
    /// - `SecureBuffer`: 32바이트 공유 비밀 키 K (OS 잠금 메모리)
    /// - `Vec<u8>`: 암호문 c
    ///
    /// # Errors
    /// - `MLKEMError::RngError`: RNG에서 난수를 얻지 못한 경우
    /// - `MLKEMError::InternalError`: 내부 연산 실패
    pub fn encaps<R: MLKEMRng>(
        ek: &MLKEMEncapsulationKey,
        rng: &mut R,
    ) -> Result<(SecureBuffer, Vec<u8>), MLKEMError> {
        let mut m = [0u8; 32];
        rng.fill_random(&mut m)?;

        Self::encaps_internal(ek.param, &ek.bytes, &m)
    }

    /// Algorithm 21: ML-KEM.Decaps(dk, c)
    ///
    /// 역캡슐화 키 `dk`와 암호문 `c`를 이용하여 공유 비밀 키 K를 복원합니다.
    /// 암호문이 변조된 경우 암묵적 거부(implicit rejection)를 수행하여
    /// 의사 난수 값을 반환합니다.
    ///
    /// # Arguments
    /// - `dk`: [`key_gen`](Self::key_gen)이 반환한 [`MLKEMDecapsulationKey`]
    /// - `c`: [`encaps`](Self::encaps)가 반환한 암호문 바이트 슬라이스
    ///
    /// # Returns
    /// 32바이트 공유 비밀 키 K를 OS 잠금 메모리([`SecureBuffer`])에 담아 반환합니다.
    ///
    /// # Errors
    /// - `MLKEMError::InvalidLength`: 암호문 길이 불일치
    /// - `MLKEMError::InternalError`: 내부 연산 실패
    pub fn decaps(dk: &MLKEMDecapsulationKey, c: &[u8]) -> Result<SecureBuffer, MLKEMError> {
        if c.len() != dk.param.ct_len() {
            return Err(MLKEMError::InvalidLength("암호문 길이 불일치"));
        }

        Self::decaps_internal(dk.param, dk.dk_buf.as_slice(), c)
    }

    //
    // 내부 인터페이스 (FIPS 203 Algorithms 16–18)
    //

    /// Algorithm 16: ML-KEM.KeyGen_internal(d, z)
    ///
    /// 32바이트 시드 d와 z로부터 캡슐화 키와 역캡슐화 키 쌍을
    /// 결정론적으로 생성합니다. 주어진 (d, z)에 대해 항상 동일한 키 쌍을
    /// 반환합니다 (KAT 테스트에 사용).
    ///
    /// # Security Note
    /// d, z는 암호학적으로 안전한 RNG로 생성해야 합니다.
    pub(crate) fn key_gen_internal(
        param: MLKEMParameter,
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Vec<u8>, SecureBuffer), MLKEMError> {
        match param {
            MLKEMParameter::MLKEM512 => keygen_impl::<2, 3>(d, z),
            MLKEMParameter::MLKEM768 => keygen_impl::<3, 2>(d, z),
            MLKEMParameter::MLKEM1024 => keygen_impl::<4, 2>(d, z),
        }
    }

    /// Algorithm 17: ML-KEM.Encaps_internal(ek, m)
    ///
    /// 캡슐화 키 ek와 32바이트 난수 m으로부터 공유 비밀 K와 암호문 c를
    /// 결정론적으로 생성합니다.
    pub(crate) fn encaps_internal(
        param: MLKEMParameter,
        ek: &[u8],
        m: &[u8; 32],
    ) -> Result<(SecureBuffer, Vec<u8>), MLKEMError> {
        match param {
            MLKEMParameter::MLKEM512 => encaps_impl::<2, 3, 2, 10, 4>(ek, m),
            MLKEMParameter::MLKEM768 => encaps_impl::<3, 2, 2, 10, 4>(ek, m),
            MLKEMParameter::MLKEM1024 => encaps_impl::<4, 2, 2, 11, 5>(ek, m),
        }
    }

    /// Algorithm 18: ML-KEM.Decaps_internal(dk, c)
    ///
    /// 역캡슐화 키 dk와 암호문 c로부터 공유 비밀 K를 복원합니다.
    /// 상수-시간 비교 및 조건 선택으로 암묵적 거부를 수행합니다.
    pub(crate) fn decaps_internal(
        param: MLKEMParameter,
        dk: &[u8],
        c: &[u8],
    ) -> Result<SecureBuffer, MLKEMError> {
        match param {
            MLKEMParameter::MLKEM512 => decaps_impl::<2, 3, 2, 10, 4>(dk, c),
            MLKEMParameter::MLKEM768 => decaps_impl::<3, 2, 2, 10, 4>(dk, c),
            MLKEMParameter::MLKEM1024 => decaps_impl::<4, 2, 2, 11, 5>(dk, c),
        }
    }
}

//
// 내부 구현 함수
//

/// Algorithm 16 구현: (ekPKE, dkPKE) ← K-PKE.KeyGen(d); dk ← dkPKE || ek || H(ek) || z
fn keygen_impl<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> Result<(Vec<u8>, SecureBuffer), MLKEMError> {
    let (ek_pke, dk_pke) = k_pke_keygen::<K, ETA1>(d)?;
    let ek = ek_pke;
    let h_ek = sha3_256(&ek)?;

    let dk_len = 768 * K + 96;
    let mut dk = SecureBuffer::new_owned(dk_len)
        .map_err(|_| MLKEMError::InternalError("SecureBuffer 할당 실패"))?;
    {
        let s = dk.as_mut_slice();
        s[..384 * K].copy_from_slice(dk_pke.as_slice());
        s[384 * K..768 * K + 32].copy_from_slice(&ek);
        s[768 * K + 32..768 * K + 64].copy_from_slice(&h_ek);
        s[768 * K + 64..768 * K + 96].copy_from_slice(z);
    }

    Ok((ek, dk))
}

/// Algorithm 17 구현: (K, r) ← G(m || H(ek)); c ← K-PKE.Encrypt(ek, m, r)
fn encaps_impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: u32,
    const DV: u32,
>(
    ek: &[u8],
    m: &[u8; 32],
) -> Result<(SecureBuffer, Vec<u8>), MLKEMError> {
    let h_ek = sha3_256(ek)?;

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_out = sha3_512(&g_input)?;

    let k_bytes: [u8; 32] = g_out[..32].try_into().unwrap();
    let r: [u8; 32] = g_out[32..].try_into().unwrap();

    let c = k_pke_encrypt::<K, ETA1, ETA2, DU, DV>(ek, m, &r)?;

    let mut k_buf = SecureBuffer::new_owned(32)
        .map_err(|_| MLKEMError::InternalError("SecureBuffer 할당 실패"))?;
    k_buf.as_mut_slice().copy_from_slice(&k_bytes);

    Ok((k_buf, c))
}

/// Algorithm 18 구현: 역캡슐화 + 상수-시간 암묵적 거부.
///
/// # Security Note
/// 암호문 비교(c vs c')와 공유 비밀 선택(K' vs K_bar)은 모두 상수-시간으로 수행됩니다.
fn decaps_impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: u32,
    const DV: u32,
>(
    dk: &[u8],
    c: &[u8],
) -> Result<SecureBuffer, MLKEMError> {
    let dk_pke = &dk[..384 * K];
    let ek_pke = &dk[384 * K..768 * K + 32];
    let h = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..768 * K + 96];

    // m' ← K-PKE.Decrypt(dkPKE, c)
    let m_prime = k_pke_decrypt::<K, DU, DV>(dk_pke, c)?;

    // (K', r') ← G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h);
    let g_out = sha3_512(&g_input)?;
    let k_prime: [u8; 32] = g_out[..32].try_into().unwrap();
    let r_prime: [u8; 32] = g_out[32..].try_into().unwrap();

    // K_bar ← J(z || c)
    let mut j_input = Vec::with_capacity(32 + c.len());
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(c);
    let k_bar = shake256_32(&j_input)?;

    // c' ← K-PKE.Encrypt(ekPKE, m', r')
    let c_prime = k_pke_encrypt::<K, ETA1, ETA2, DU, DV>(ek_pke, &m_prime, &r_prime)?;

    // 상수-시간 비교: c == c'
    let eq = ct_bytes_eq(c, &c_prime);

    // 상수-시간 조건 선택: eq → K', ¬eq → K_bar
    let mut k_out = [0u8; 32];
    for i in 0..32 {
        k_out[i] = u8::ct_select(&k_prime[i], &k_bar[i], eq);
    }

    let mut k_buf = SecureBuffer::new_owned(32)
        .map_err(|_| MLKEMError::InternalError("SecureBuffer 할당 실패"))?;
    k_buf.as_mut_slice().copy_from_slice(&k_out);

    Ok(k_buf)
}

//
// 내부 유틸리티
//

/// 두 바이트 슬라이스를 상수-시간으로 비교합니다.
///
/// # Security Note
/// 길이가 다르면 FALSE를 반환하되, 길이 차이 자체는 비밀이 아닙니다.
/// (암호문 길이는 파라미터 셋에 의해 결정되는 공개 정보)
fn ct_bytes_eq(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return 0u8.ct_eq(&1u8);
    }
    let mut acc = 0u8.ct_eq(&0u8);
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc & x.ct_eq(y);
    }
    acc
}

/// FIPS 203 캡슐화 키 모듈러스 검사.
/// ek[0..384*k] 내 모든 12-bit 계수가 q 미만인지 확인합니다.
fn validate_ek_coefficients(ek: &[u8], k: usize) -> bool {
    for i in 0..k {
        let decoded = byte_decode(&ek[i * 384..(i + 1) * 384], 12);
        for &coeff in decoded.iter() {
            if coeff >= crate::field::Q {
                return false;
            }
        }
    }
    true
}

/// `DrbgError`를 `MLKEMError::RngError`로 변환
#[inline(always)]
fn drbg_err(e: DrbgError) -> MLKEMError {
    match e {
        DrbgError::ReseedRequired => {
            MLKEMError::RngError("RNG reseed 필요: reseed() 호출 후 재시도")
        }
        DrbgError::EntropyTooShort => MLKEMError::RngError("엔트로피 길이 부족"),
        DrbgError::NonceTooShort => MLKEMError::RngError("Nonce 길이 부족"),
        DrbgError::RequestTooLarge => MLKEMError::RngError("요청 크기 초과"),
        DrbgError::AllocationFailed => MLKEMError::RngError("RNG 메모리 할당 실패"),
        _ => MLKEMError::RngError("RNG 내부 오류"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_intt_roundtrip() {
        use crate::ntt::{N, intt, ntt};
        let mut f = [0i32; N];
        for (i, val) in f.iter_mut().enumerate() {
            *val = (i as i32 * 13 + 7) % crate::field::Q;
        }
        let original = f;
        ntt(&mut f);
        intt(&mut f);
        assert_eq!(f, original, "NTT/INTT roundtrip failed");
    }

    #[test]
    fn compress_decompress_roundtrip() {
        use crate::encode::{compress, decompress};
        let q = crate::field::Q;
        for d in [1u32, 4, 5, 10, 11] {
            for x in (0..q).step_by(17) {
                let c = compress(x, d);
                let r = decompress(c, d);
                let raw = (x - r).rem_euclid(q);
                let diff = raw.min(q - raw);
                let max_err = (q + (1 << d)) / (1 << (d + 1));
                assert!(
                    diff <= max_err,
                    "compress/decompress error too large: d={d}, x={x}, c={c}, r={r}, diff={diff}, max={max_err}"
                );
            }
        }
    }

    #[test]
    fn kpke_roundtrip_768() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke::k_pke_keygen::<3, 2>(&d).unwrap();

        let m = [0xABu8; 32];
        let r = [0xCDu8; 32];

        let c = k_pke::k_pke_encrypt::<3, 2, 2, 10, 4>(&ek, &m, &r).unwrap();
        let m_out = k_pke::k_pke_decrypt::<3, 10, 4>(dk.as_slice(), &c).unwrap();

        assert_eq!(m, m_out, "K-PKE encrypt/decrypt roundtrip failed");
    }

    #[test]
    fn keygen_encaps_decaps_512() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM512, &mut rng).unwrap();
        assert_eq!(ek.len(), MLKEM512_EK_LEN);
        assert_eq!(dk.len(), MLKEM512_DK_LEN);

        let (k1, ct) = MLKEM::encaps(&ek, &mut rng).unwrap();
        assert_eq!(ct.len(), MLKEM512_CT_LEN);
        assert_eq!(k1.len(), 32);

        let k2 = MLKEM::decaps(&dk, &ct).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn keygen_encaps_decaps_768() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM768, &mut rng).unwrap();
        assert_eq!(ek.len(), MLKEM768_EK_LEN);
        assert_eq!(dk.len(), MLKEM768_DK_LEN);

        let (k1, ct) = MLKEM::encaps(&ek, &mut rng).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);

        let k2 = MLKEM::decaps(&dk, &ct).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn keygen_encaps_decaps_1024() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM1024, &mut rng).unwrap();
        assert_eq!(ek.len(), MLKEM1024_EK_LEN);
        assert_eq!(dk.len(), MLKEM1024_DK_LEN);

        let (k1, ct) = MLKEM::encaps(&ek, &mut rng).unwrap();
        assert_eq!(ct.len(), MLKEM1024_CT_LEN);

        let k2 = MLKEM::decaps(&dk, &ct).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn implicit_rejection() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM768, &mut rng).unwrap();
        let (k1, mut ct) = MLKEM::encaps(&ek, &mut rng).unwrap();

        ct[0] ^= 0xFF;

        let k2 = MLKEM::decaps(&dk, &ct).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn invalid_ek_length() {
        let result = MLKEMEncapsulationKey::from_bytes(MLKEMParameter::MLKEM768, vec![0u8; 100]);
        assert!(matches!(result, Err(MLKEMError::InvalidLength(_))));
    }

    #[test]
    fn invalid_dk_length() {
        let result = MLKEMDecapsulationKey::from_bytes(MLKEMParameter::MLKEM768, &[0u8; 100]);
        assert!(matches!(result, Err(MLKEMError::InvalidLength(_))));
    }

    #[test]
    fn invalid_ct_length() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (_, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM768, &mut rng).unwrap();
        let result = MLKEM::decaps(&dk, &[0u8; 100]);
        assert!(matches!(result, Err(MLKEMError::InvalidLength(_))));
    }

    #[test]
    fn ek_modulus_check() {
        let bad_ek = vec![0xFFu8; MLKEM768_EK_LEN];
        let result = MLKEMEncapsulationKey::from_bytes(MLKEMParameter::MLKEM768, bad_ek);
        assert!(matches!(result, Err(MLKEMError::InvalidEncapsulationKey)));
    }

    #[test]
    fn key_roundtrip() {
        let mut rng = HashDRBGRng::new_from_os(None).unwrap();
        let (ek, dk) = MLKEM::key_gen(MLKEMParameter::MLKEM768, &mut rng).unwrap();

        let ek2 = MLKEMEncapsulationKey::from_bytes(ek.param(), ek.as_bytes().to_vec()).unwrap();
        let dk2 = MLKEMDecapsulationKey::from_bytes(dk.param(), dk.as_bytes()).unwrap();

        let (k1, ct) = MLKEM::encaps(&ek2, &mut rng).unwrap();
        let k2 = MLKEM::decaps(&dk2, &ct).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }
}
