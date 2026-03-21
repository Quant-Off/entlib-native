//! FIPS 204 명세에 따른 모듈 격자 기반 전자 서명(Module Lattice-based Digital Signature Algorithm, ML-DSA)
//! 알고리즘 구현 모듈입니다. 해당 명세 서명 스키마의 최상위 공개 인터페이스를 제공합니다.
//!
//! # Example
//! ```rust,ignore
//! use entlib_native_mldsa::{MLDSA, MLDSAParameter, HashDRBGRng};
//!
//! // 1. RNG 초기화 (OS 엔트로피 소스 사용 — 임의 엔트로피 주입 불가)
//! let mut rng = HashDRBGRng::new_from_os(None).unwrap();
//!
//! // 2. 키 쌍 생성 (ML-DSA-44)
//! let (pk_bytes, sk_buf) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).unwrap();
//!
//! // 3. 서명
//! let message = b"Hello, ML-DSA!";
//! let ctx     = b"";
//! let sig = MLDSA::sign(MLDSAParameter::MLDSA44, &sk_buf, message, ctx, &mut rng).unwrap();
//!
//! // 4. 검증
//! let ok = MLDSA::verify(MLDSAParameter::MLDSA44, &pk_bytes, message, &sig, ctx).unwrap();
//! assert!(ok);
//! ```

use super::mldsa44::{
    BETA_44, ETA_44, GAMMA1_44, GAMMA2_44, K_44, L_44, LAMBDA_44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN,
    MLDSA44_SK_LEN, OMEGA_44, TAU_44,
};
use super::mldsa65::{
    BETA_65, ETA_65, GAMMA1_65, GAMMA2_65, K_65, L_65, LAMBDA_65, MLDSA65_PK_LEN, MLDSA65_SIG_LEN,
    MLDSA65_SK_LEN, OMEGA_65, TAU_65,
};
use super::mldsa87::{
    BETA_87, ETA_87, GAMMA1_87, GAMMA2_87, K_87, L_87, LAMBDA_87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN,
    MLDSA87_SK_LEN, OMEGA_87, TAU_87,
};
use crate::error::MLDSAError;
use crate::mldsa_keys::keygen_internal;
use crate::mldsa_keys::{
    MLDSAPrivateKey as SkComponents, MLDSAPrivateKeyTrait, MLDSAPublicKey as PkComponents,
    MLDSAPublicKeyTrait,
};
use crate::mldsa_sign::{sign_internal_impl, verify_internal_impl};
use entlib_native_rng::{DrbgError, HashDRBGSHA512};
use entlib_native_secure_buffer::SecureBuffer;

//
// RNG 추상화 트레이트
//

/// ML-DSA 연산에 사용되는 암호학적으로 안전한 난수 생성기 트레이트.
///
/// 이 트레이트를 구현하는 타입은 NIST SP 800-90A Rev.1 이상의 보안 강도를
/// 제공하는 결정론적 난수 비트 생성기(DRBG)여야 합니다.
///
/// # Features
/// - [`HashDRBGRng`]: NIST Hash_DRBG (SHA-512, Security Strength 256-bit)
/// - [`CtrDRBGRng`]: NIST CTR_DRBG (AES-256-CTR) **향후 개발 예정**
pub trait MLDSARng {
    /// `dest` 슬라이스를 암호학적으로 안전한 난수 바이트로 채웁니다.
    ///
    /// # Errors
    /// - `MLDSAError::RngError`: RNG 내부 오류 또는 reseed가 필요한 경우
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLDSAError>;
}

//
// Hash_DRBG 래퍼
//

/// NIST SP 800-90A Rev.1 Hash_DRBG (SHA-512 기반) RNG 래퍼.
///
/// ML-DSA 키 생성 및 서명에 사용하도록 설계되었습니다.
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
    /// - `MLDSAError::RngError`: OS 엔트로피 소스 접근 실패 또는 내부 오류
    pub fn new_from_os(personalization_string: Option<&[u8]>) -> Result<Self, MLDSAError> {
        let inner = HashDRBGSHA512::new_from_os(personalization_string).map_err(drbg_err)?;
        Ok(Self { inner })
    }

    /// 현재 RNG 상태를 새 엔트로피로 갱신합니다.
    ///
    /// `MLDSAError::RngError(ReseedRequired)`를 수신한 경우 반드시 호출해야 합니다.
    pub fn reseed(
        &mut self,
        entropy_input: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), MLDSAError> {
        self.inner
            .reseed(entropy_input, additional_input)
            .map_err(drbg_err)
    }
}

impl MLDSARng for HashDRBGRng {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLDSAError> {
        self.inner.generate(dest, None).map_err(drbg_err)
    }
}

//
// CTR_DRBG 래퍼 (미구현 — 확장 예약)
//

/// NIST SP 800-90A Rev.1 CTR_DRBG (AES-256-CTR 기반) RNG 래퍼.
///
/// AES-256-CTR 구현이 준비되면 이 구조체에 내부 상태를 추가하고
/// [`MLDSARng`] impl 내에서 CTR_DRBG 알고리즘을 구현합니다.
///
/// # Security Note
/// **현재 미구현 상태입니다.**
/// AES-256 블록 암호 구현 크레이트(`entlib-native-aes`) 완료 후 제공될 예정입니다.
pub struct CtrDRBGRng {
    // todo: AES-256-CTR DRBG 상태 여기에 추가하면 됌
    // key:   SecureBuffer  (256-bit)
    // value: SecureBuffer  (128-bit, AES block size)
    // reseed_counter: u64
    _private: (),
}

impl CtrDRBGRng {
    /// CTR_DRBG를 초기화합니다.
    ///
    /// **현재 항상 `MLDSAError::NotImplemented`를 반환합니다.**
    pub fn new(_entropy_input: &[u8], _nonce: &[u8]) -> Result<Self, MLDSAError> {
        Err(MLDSAError::NotImplemented(
            "CTR_DRBG: AES-256 구현 완료 후 제공됩니다",
        ))
    }
}

impl MLDSARng for CtrDRBGRng {
    fn fill_random(&mut self, _dest: &mut [u8]) -> Result<(), MLDSAError> {
        Err(MLDSAError::NotImplemented(
            "CTR_DRBG: AES-256 구현 완료 후 제공됩니다",
        ))
    }
}

//
// ML-DSA 파라미터 셋
//

/// NIST FIPS 204에 정의된 ML-DSA 파라미터 셋
///
/// | 파라미터 셋 | NIST 카테고리 | pk 크기 | sk 크기 | 서명 크기 |
/// |-------------|:------------:|--------:|--------:|----------:|
/// | MLDSA44     | 2 (AES-128 동급) | 1312 B | 2560 B | 2420 B |
/// | MLDSA65     | 3 (AES-192 동급) | 1952 B | 4032 B | 3309 B |
/// | MLDSA87     | 5 (AES-256 동급) | 2592 B | 4896 B | 4627 B |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MLDSAParameter {
    /// ML-DSA-44: NIST 보안 카테고리 2 (Security Strength ≥ 128-bit)
    MLDSA44,
    /// ML-DSA-65: NIST 보안 카테고리 3 (Security Strength ≥ 192-bit)
    MLDSA65,
    /// ML-DSA-87: NIST 보안 카테고리 5 (Security Strength ≥ 256-bit)
    MLDSA87,
}

impl MLDSAParameter {
    /// 공개 키 바이트 길이를 반환합니다.
    #[inline]
    pub const fn pk_len(self) -> usize {
        match self {
            MLDSAParameter::MLDSA44 => 1312,
            MLDSAParameter::MLDSA65 => 1952,
            MLDSAParameter::MLDSA87 => 2592,
        }
    }

    /// 비밀 키 바이트 길이를 반환합니다.
    #[inline]
    pub const fn sk_len(self) -> usize {
        match self {
            MLDSAParameter::MLDSA44 => 2560,
            MLDSAParameter::MLDSA65 => 4032,
            MLDSAParameter::MLDSA87 => 4896,
        }
    }

    /// 서명 바이트 길이를 반환합니다.
    #[inline]
    pub const fn sig_len(self) -> usize {
        match self {
            MLDSAParameter::MLDSA44 => 2420,
            MLDSAParameter::MLDSA65 => 3309,
            MLDSAParameter::MLDSA87 => 4627,
        }
    }
}

//
// 공개 키 / 비밀 키 타입
//

/// ML-DSA 공개 키.
///
/// 인코딩된 공개 키 바이트(`ρ || SimpleBitPack(t1)`)와 파라미터 셋을 함께 보유합니다.
/// [`MLDSA::key_gen`]이 반환하며, [`MLDSA::verify`]에 직접 전달할 수 있습니다.
pub struct MLDSAPublicKey {
    param: MLDSAParameter,
    bytes: Vec<u8>,
}

impl MLDSAPublicKey {
    /// 이 공개 키가 속한 파라미터 셋을 반환합니다.
    #[inline]
    pub fn param(&self) -> MLDSAParameter {
        self.param
    }

    /// 인코딩된 공개 키 바이트 슬라이스를 반환합니다.
    ///
    /// 반환값은 FIPS 204 `pkEncode` 출력(`ρ || SimpleBitPack(t1, 10)`)과 동일합니다.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 인코딩된 공개 키의 바이트 길이를 반환합니다.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// 공개 키가 비어 있으면 `true`를 반환합니다 (정상적으로 생성된 키에서는 발생하지 않습니다).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// ML-DSA 비밀 키.
///
/// 직렬화된 비밀 키 바이트를 OS 레벨 잠금 메모리([`SecureBuffer`])에 보관합니다.
/// `Drop` 시점에 메모리가 자동으로 소거(Zeroize)됩니다.
///
/// [`MLDSA::key_gen`]이 반환하며, [`MLDSA::sign`]에 직접 전달할 수 있습니다.
pub struct MLDSAPrivateKey {
    param: MLDSAParameter,
    sk_buf: SecureBuffer,
}

impl MLDSAPrivateKey {
    /// 이 비밀 키가 속한 파라미터 셋을 반환합니다.
    #[inline]
    pub fn param(&self) -> MLDSAParameter {
        self.param
    }

    /// 인코딩된 비밀 키의 바이트 길이를 반환합니다.
    #[inline]
    pub fn len(&self) -> usize {
        self.sk_buf.len()
    }

    /// 비밀 키가 비어 있으면 `true`를 반환합니다 (정상적으로 생성된 키에서는 발생하지 않습니다).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sk_buf.is_empty()
    }
}

//
// MLDSA 공개 API
//

/// NIST FIPS 204 ML-DSA 서명 스키마의 최상위 진입점.
///
/// 모든 메소드는 정적(static)이며, 파라미터 셋 정보는 키 타입에 내장됩니다.
pub struct MLDSA;

impl MLDSA {
    //
    // 외부 인터페이스 (FIPS 204 Algorithms 1–3)
    //

    /// Algorithm 1: ML-DSA.KeyGen(λ)
    ///
    /// RNG로 32바이트 시드 ξ를 생성하고, 이를 바탕으로 공개 키와 비밀 키 쌍을
    /// 결정론적으로 유도합니다.
    ///
    /// # Returns
    /// - [`MLDSAPublicKey`]: 파라미터 셋과 인코딩된 공개 키 바이트를 보유
    /// - [`MLDSAPrivateKey`]: 비밀 키를 OS 잠금 메모리([`SecureBuffer`])에 보관 (Drop 시 자동 소거)
    ///
    /// # Errors
    /// - `MLDSAError::RngError`: RNG에서 시드를 얻지 못한 경우
    /// - `MLDSAError::InternalError`: 내부 연산 실패
    pub fn key_gen<R: MLDSARng>(
        param: MLDSAParameter,
        rng: &mut R,
    ) -> Result<(MLDSAPublicKey, MLDSAPrivateKey), MLDSAError> {
        // 32바이트 시드 ξ를 RNG에서 생성
        let mut xi = [0u8; 32];
        rng.fill_random(&mut xi)?;

        let (pk_bytes, sk_buf) = Self::key_gen_internal(param, &xi)?;
        Ok((
            MLDSAPublicKey {
                param,
                bytes: pk_bytes,
            },
            MLDSAPrivateKey { param, sk_buf },
        ))
    }

    /// Algorithm 2: ML-DSA.Sign(dk, M, ctx)
    ///
    /// 비밀 키 `sk`와 메시지 `message`를 이용하여 디지털 서명을 생성합니다.
    /// 서명은 RNG에서 얻은 32바이트 rnd 값으로 헤지드(hedged) 처리됩니다.
    /// 파라미터 셋은 `sk`에 내장되어 있으므로 별도로 지정하지 않습니다.
    ///
    /// # Arguments
    /// - `sk`: [`key_gen`](Self::key_gen)이 반환한 [`MLDSAPrivateKey`]
    /// - `message`: 서명할 메시지 바이트 슬라이스 (크기 제한 없음)
    /// - `ctx`: 응용 컨텍스트 문자열 (`ctx.len() ≤ 255`, FIPS 204 Section 5.2)
    /// - `rng`: 헤지드 서명에 사용할 RNG
    ///
    /// # Returns
    /// 직렬화된 서명을 OS 잠금 메모리([`SecureBuffer`])에 담아 반환합니다.
    /// 길이 = `sk.param().sig_len()`
    pub fn sign<R: MLDSARng>(
        sk: &MLDSAPrivateKey,
        message: &[u8],
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<SecureBuffer, MLDSAError> {
        // ctx 길이 검증: FIPS 204 Section 5.2, 255바이트 이하
        if ctx.len() > 255 {
            return Err(MLDSAError::ContextTooLong);
        }

        // 32바이트 rnd를 RNG에서 생성 (헤지드 서명)
        let mut rnd = [0u8; 32];
        rng.fill_random(&mut rnd)?;

        // M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M
        let m_prime = build_m_prime(0x00, ctx, message);

        Self::sign_internal(sk.param, &sk.sk_buf, &m_prime, &rnd)
    }

    /// Algorithm 3: ML-DSA.Verify(ek, M, σ, ctx)
    ///
    /// 공개 키 `pk`를 이용하여 서명 `sig`가 `message`에 대한 유효한
    /// ML-DSA 서명인지 검증합니다.
    /// 파라미터 셋은 `pk`에 내장되어 있으므로 별도로 지정하지 않습니다.
    ///
    /// # Arguments
    /// - `pk`: [`key_gen`](Self::key_gen)이 반환한 [`MLDSAPublicKey`]
    /// - `message`: 원본 메시지 바이트 슬라이스
    /// - `sig`: 검증할 서명 바이트 슬라이스
    /// - `ctx`: 서명 시 사용한 컨텍스트 문자열 (동일해야 함)
    ///
    /// # Returns
    /// - `Ok(true)`: 서명 유효
    /// - `Ok(false)`: 서명 무효 (상수-시간 비교)
    /// - `Err(MLDSAError::ContextTooLong)`: ctx가 255바이트 초과
    pub fn verify(
        pk: &MLDSAPublicKey,
        message: &[u8],
        sig: &[u8],
        ctx: &[u8],
    ) -> Result<bool, MLDSAError> {
        if ctx.len() > 255 {
            return Err(MLDSAError::ContextTooLong);
        }

        // 서명 길이 사전 검증 (빠른 거부)
        if sig.len() != pk.param.sig_len() {
            return Ok(false);
        }

        // M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M
        let m_prime = build_m_prime(0x00, ctx, message);

        Self::verify_internal(pk.param, &pk.bytes, &m_prime, sig)
    }

    //
    // 내부 인터페이스 (FIPS 204 Algorithms 4–7)
    //

    /// Algorithm 4: ML-DSA.KeyGen_internal(ξ)
    ///
    /// 32바이트 시드 ξ로부터 공개 키와 비밀 키 쌍을 결정론적으로 생성합니다.
    /// 주어진 ξ에 대해 항상 동일한 키 쌍을 반환합니다 (KAT 테스트에 사용).
    ///
    /// # Security Note
    /// ξ는 암호학적으로 안전한 RNG로 생성해야 합니다.
    /// 예측 가능하거나 재사용된 ξ는 심각한 보안 취약점을 야기합니다.
    pub(crate) fn key_gen_internal(
        param: MLDSAParameter,
        xi: &[u8; 32],
    ) -> Result<(Vec<u8>, SecureBuffer), MLDSAError> {
        match param {
            MLDSAParameter::MLDSA44 => {
                keygen_encode::<K_44, L_44, ETA_44, MLDSA44_PK_LEN, MLDSA44_SK_LEN>(xi)
            }
            MLDSAParameter::MLDSA65 => {
                keygen_encode::<K_65, L_65, ETA_65, MLDSA65_PK_LEN, MLDSA65_SK_LEN>(xi)
            }
            MLDSAParameter::MLDSA87 => {
                keygen_encode::<K_87, L_87, ETA_87, MLDSA87_PK_LEN, MLDSA87_SK_LEN>(xi)
            }
        }
    }

    /// Algorithm 5: ML-DSA.Sign_internal(dk, M', rnd)
    ///
    /// 결정론적 서명 내부 알고리즘. `rnd`가 [0u8; 32]이면 순수 결정론적 서명,
    /// 그 외에는 헤지드(hedged) 서명입니다.
    ///
    /// 거절 샘플링 기반 서명 루프(ExpandMask, Decompose, MakeHint, SigEncode)를
    /// 파라미터 셋별로 단형화하여 호출합니다.
    pub(crate) fn sign_internal(
        param: MLDSAParameter,
        sk_buf: &SecureBuffer,
        m_prime: &[u8],
        rnd: &[u8; 32],
    ) -> Result<SecureBuffer, MLDSAError> {
        match param {
            MLDSAParameter::MLDSA44 => sign_internal_impl::<
                K_44,
                L_44,
                ETA_44,
                GAMMA1_44,
                GAMMA2_44,
                BETA_44,
                OMEGA_44,
                LAMBDA_44,
                TAU_44,
                MLDSA44_SK_LEN,
                MLDSA44_SIG_LEN,
            >(sk_buf, m_prime, rnd),
            MLDSAParameter::MLDSA65 => sign_internal_impl::<
                K_65,
                L_65,
                ETA_65,
                GAMMA1_65,
                GAMMA2_65,
                BETA_65,
                OMEGA_65,
                LAMBDA_65,
                TAU_65,
                MLDSA65_SK_LEN,
                MLDSA65_SIG_LEN,
            >(sk_buf, m_prime, rnd),
            MLDSAParameter::MLDSA87 => sign_internal_impl::<
                K_87,
                L_87,
                ETA_87,
                GAMMA1_87,
                GAMMA2_87,
                BETA_87,
                OMEGA_87,
                LAMBDA_87,
                TAU_87,
                MLDSA87_SK_LEN,
                MLDSA87_SIG_LEN,
            >(sk_buf, m_prime, rnd),
        }
    }

    /// Algorithm 7: ML-DSA.Verify_internal(ek, M', σ)
    ///
    /// 결정론적 검증 내부 알고리즘.
    /// w1' 재구성 및 챌린지 해시 비교를 파라미터 셋별로 단형화하여 호출합니다.
    pub(crate) fn verify_internal(
        param: MLDSAParameter,
        pk_bytes: &[u8],
        m_prime: &[u8],
        sig: &[u8],
    ) -> Result<bool, MLDSAError> {
        match param {
            MLDSAParameter::MLDSA44 => verify_internal_impl::<
                K_44,
                L_44,
                GAMMA1_44,
                GAMMA2_44,
                BETA_44,
                OMEGA_44,
                LAMBDA_44,
                TAU_44,
                MLDSA44_PK_LEN,
                MLDSA44_SIG_LEN,
            >(pk_bytes, m_prime, sig),
            MLDSAParameter::MLDSA65 => verify_internal_impl::<
                K_65,
                L_65,
                GAMMA1_65,
                GAMMA2_65,
                BETA_65,
                OMEGA_65,
                LAMBDA_65,
                TAU_65,
                MLDSA65_PK_LEN,
                MLDSA65_SIG_LEN,
            >(pk_bytes, m_prime, sig),
            MLDSAParameter::MLDSA87 => verify_internal_impl::<
                K_87,
                L_87,
                GAMMA1_87,
                GAMMA2_87,
                BETA_87,
                OMEGA_87,
                LAMBDA_87,
                TAU_87,
                MLDSA87_PK_LEN,
                MLDSA87_SIG_LEN,
            >(pk_bytes, m_prime, sig),
        }
    }
}

//
// 내부 유틸리티
//

/// M' 구성: `domain_sep || IntegerToBytes(|ctx|, 1) || ctx || M`
///
/// FIPS 204 Section 5.2에 따른 외부 인터페이스 메시지 전처리.
/// - ML-DSA.Sign/Verify: domain_sep = 0x00
/// - HashML-DSA.Sign/Verify: domain_sep = 0x01
fn build_m_prime(domain_sep: u8, ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
    m_prime.push(domain_sep);
    m_prime.push(ctx.len() as u8); // |ctx| ≤ 255이므로 u8 안전
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(message);
    m_prime
}

/// 키 생성 + 인코딩 헬퍼 (파라미터 셋별 단형화)
///
/// `keygen_internal`을 호출하고 pk를 바이트로, sk를 SecureBuffer로 직렬화합니다.
fn keygen_encode<
    const K: usize,
    const L: usize,
    const ETA: i32,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    xi: &[u8; 32],
) -> Result<(Vec<u8>, SecureBuffer), MLDSAError> {
    let (pk, sk) = keygen_internal::<K, L, ETA>(xi)?;

    // pkEncode: ρ || SimpleBitPack(t1, 10) — PK_LEN 바이트
    let pk_bytes = <PkComponents<K> as MLDSAPublicKeyTrait<K, PK_LEN>>::pk_encode(&pk);

    // skEncode: SecureBuffer (OS 잠금 메모리)
    let sk_buf = <SkComponents<K, L, ETA> as MLDSAPrivateKeyTrait<K, L, SK_LEN>>::sk_encode(&sk)?;

    Ok((pk_bytes.to_vec(), sk_buf))
}

/// `DrbgError`를 `MLDSAError::RngError`로 변환
#[inline(always)]
fn drbg_err(e: DrbgError) -> MLDSAError {
    match e {
        DrbgError::ReseedRequired => {
            MLDSAError::RngError("RNG reseed 필요: reseed() 호출 후 재시도")
        }
        DrbgError::EntropyTooShort => MLDSAError::RngError("엔트로피 길이 부족"),
        DrbgError::NonceTooShort => MLDSAError::RngError("Nonce 길이 부족"),
        DrbgError::RequestTooLarge => MLDSAError::RngError("요청 크기 초과"),
        DrbgError::AllocationFailed => MLDSAError::RngError("RNG 메모리 할당 실패"),
        _ => MLDSAError::RngError("RNG 내부 오류"),
    }
}
