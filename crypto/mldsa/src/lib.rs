// 어중간한 에러는 모두 InternalError 로 모호하게
mod error;
mod field;
mod mldsa;
mod mldsa_keys;
mod mldsa_sign;
mod ntt;
mod pack;
mod poly;
mod sample;

#[cfg(test)]
mod _mldsa_test;

//
// Commons
//

/// 모듈러스 q
pub(crate) const Q: i32 = 8380417;
/// t에서 버려지는 비트 수
pub(crate) const D: usize = 13;
// Z_q 내의 512 제곱근
// pub(crate) const ZETA: i32 = 1753;
/// 몽고메리 환원을 위한 상수 q^(-1) mod 2^32
pub(crate) const Q_INV: i32 = 58728449;
pub(crate) const SEED_LEN: usize = 32;

//
// ML-DSA-44 Params
//

mod mldsa44 {
    /// ML-DSA-44 공개 키 길이
    pub(crate) const MLDSA44_PK_LEN: usize = 1312;
    /// ML-DSA-44 비밀 키 길이
    pub(crate) const MLDSA44_SK_LEN: usize = 2560;
    /// ML-DSA-44 서명 길이
    pub(crate) const MLDSA44_SIG_LEN: usize = 2420;
    /// 행렬 A의 k 차원
    pub(crate) const K_44: usize = 4;
    /// 행렬 A의 l 차원
    pub(crate) const L_44: usize = 4;
    /// 개인키(Private key) 계수 범위 η (eta)
    pub(crate) const ETA_44: i32 = 2;
    /// 다항식 c에서 ±1의 개수 τ (tau)
    pub(crate) const TAU_44: usize = 39;
    /// β = τ * η
    pub(crate) const BETA_44: i32 = 78;
    /// c 틸다(tilde)의 충돌 강도 λ (lambda)
    pub(crate) const LAMBDA_44: usize = 128;
    /// y의 계수 범위 γ1 (gamma1) = 2^17
    pub(crate) const GAMMA1_44: i32 = 131072;
    /// 하위 차수 반올림 범위 γ2 (gamma2) = (q - 1) / 88
    pub(crate) const GAMMA2_44: i32 = 95232;
    /// 힌트 h에서 1의 최대 개수 ω (omega)
    pub(crate) const OMEGA_44: usize = 80;
}

//
// ML-DSA-65 Params
//

mod mldsa65 {
    /// ML-DSA-65 공개 키 길이
    pub(crate) const MLDSA65_PK_LEN: usize = 1952;
    /// ML-DSA-65 비밀 키 길이
    pub(crate) const MLDSA65_SK_LEN: usize = 4032;
    /// ML-DSA-65 서명 길이
    pub(crate) const MLDSA65_SIG_LEN: usize = 3309;
    /// 행렬 A의 k 차원
    pub(crate) const K_65: usize = 6;
    /// 행렬 A의 l 차원
    pub(crate) const L_65: usize = 5;
    /// 개인키(Private key) 계수 범위 η (eta)
    pub(crate) const ETA_65: i32 = 4;
    /// 다항식 c에서 ±1의 개수 τ (tau)
    pub(crate) const TAU_65: usize = 49;
    /// β = τ * η
    pub(crate) const BETA_65: i32 = 196;
    /// c 틸다(tilde)의 충돌 강도 λ (lambda)
    pub(crate) const LAMBDA_65: usize = 192;
    /// y의 계수 범위 γ1 (gamma1) = 2^19
    pub(crate) const GAMMA1_65: i32 = 524288;
    /// 하위 차수 반올림 범위 γ2 (gamma2) = (q - 1) / 32
    pub(crate) const GAMMA2_65: i32 = 261888;
    /// 힌트 h에서 1의 최대 개수 ω (omega)
    pub(crate) const OMEGA_65: usize = 55;
}

//
// ML-DSA-87 Params
//

mod mldsa87 {
    /// ML-DSA-87 공개 키 길이
    pub(crate) const MLDSA87_PK_LEN: usize = 2592;
    /// ML-DSA-87 비밀 키 길이
    pub(crate) const MLDSA87_SK_LEN: usize = 4896;
    /// ML-DSA-87 서명 길이
    pub(crate) const MLDSA87_SIG_LEN: usize = 4627;
    /// 행렬 A의 k 차원
    pub(crate) const K_87: usize = 8;
    /// 행렬 A의 l 차원
    pub(crate) const L_87: usize = 7;
    /// 개인키(Private key) 계수 범위 η (eta)
    pub(crate) const ETA_87: i32 = 2;
    /// 다항식 c에서 ±1의 개수 τ (tau)
    pub(crate) const TAU_87: usize = 60;
    /// β = τ * η
    pub(crate) const BETA_87: i32 = 120;
    /// c 틸다(tilde)의 충돌 강도 λ (lambda)
    pub(crate) const LAMBDA_87: usize = 256;
    /// y의 계수 범위 γ1 (gamma1) = 2^19
    pub(crate) const GAMMA1_87: i32 = 524288;
    /// 하위 차수 반올림 범위 γ2 (gamma2) = (q - 1) / 32
    pub(crate) const GAMMA2_87: i32 = 261888;
    /// 힌트 h에서 1의 최대 개수 ω (omega)
    pub(crate) const OMEGA_87: usize = 75;
}

//
// API Signature
//

pub use error::MLDSAError;
pub use mldsa::{
    CtrDRBGRng, HashDRBGRng, MLDSA, MLDSAParameter, MLDSAPrivateKey, MLDSAPublicKey, MLDSARng,
};

// todo: 아마도 유닛 테스트는 src/ 에 추가
//       외부 시그니처에 대한 테스트는 tests/
