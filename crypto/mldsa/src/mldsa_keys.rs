use crate::error::MLDSAError;
use crate::error::MLDSAError::InvalidLength;
use crate::field::Fq;
use crate::ntt::N;
use crate::pack::{
    poly_simple_bit_pack_t1, poly_simple_bit_unpack_t1, polyvec_bit_pack_eta, polyvec_bit_pack_t0,
    polyvec_bit_unpack_eta, polyvec_bit_unpack_t0,
};
use crate::poly::PolyVec;
use crate::sample::{expand_a, expand_s};
use crate::{Q, SEED_LEN};
use entlib_native_constant_time::traits::{ConstantTimeIsNegative, ConstantTimeSelect};
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha3::api::SHAKE256;

//
// 트레이트 정의
//

pub trait MLDSAPublicKeyTrait<const K: usize, const PK_LEN: usize> {
    /// Algorithm 22: pkEncode(ρ, t1)
    ///
    /// 공개 키를 바이트 문자열로 인코딩합니다.
    /// 입력: ρ ∈ 𝔹^32, t1 ∈ R_q^k (계수 ∈ [0, 2^(bitlen(q-1)-d) - 1])
    /// 출력: pk ∈ 𝔹^(32 + 32k·(bitlen(q-1)-d))
    fn pk_encode(&self) -> [u8; PK_LEN];

    /// Algorithm 23: pkDecode(pk)
    ///
    /// pkEncode의 역연산.
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self;
}

pub trait MLDSAPrivateKeyTrait<const K: usize, const L: usize, const SK_LEN: usize> {
    /// Algorithm 24: skEncode(ρ, K, tr, s1, s2, t0)
    ///
    /// 비밀 키를 SecureBuffer에 직렬화합니다. 민감 데이터는 OS 레벨로 잠긴
    /// 물리 메모리에 저장되며, Drop 시 자동 소거됩니다.
    fn sk_encode(&self) -> Result<SecureBuffer, MLDSAError>;

    /// Algorithm 25: skDecode(sk)
    ///
    /// skEncode의 역연산. 길이 검증 후 필드를 복원합니다.
    fn sk_decode(sk: &SecureBuffer) -> Result<Self, MLDSAError>
    where
        Self: Sized;
}

//
// 키 구조체
//

/// ML-DSA 공개 키 구조체
pub struct MLDSAPublicKey<const K: usize> {
    pub(crate) rho: [u8; SEED_LEN],
    pub(crate) t1: PolyVec<K>,
}

/// ML-DSA 비밀 키 구조체
///
/// `ETA`는 s1, s2의 계수 범위 [-η, η]를 결정하는 파라미터로,
/// sk_encode/sk_decode 시 올바른 비트 너비를 계산하는 데 사용됩니다.
/// 비밀 키는 SecureBuffer를 통해 외부에 직렬화하며, 구조체 자체는
/// 스택에 임시로만 존재합니다.
pub struct MLDSAPrivateKey<const K: usize, const L: usize, const ETA: i32> {
    pub(crate) rho: [u8; 32],
    pub(crate) k_seed: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s1: PolyVec<L>,
    pub(crate) s2: PolyVec<K>,
    pub(crate) t0: PolyVec<K>,
}

//
// 내부 유틸리티
//

/// bitlen(2η): s1, s2 인코딩에 사용하는 계수당 비트 수를 반환합니다.
///
/// - η=2 → bitlen(4) = 3
/// - η=4 → bitlen(8) = 4
#[inline(always)]
fn eta_bit_width(eta: i32) -> usize {
    (u32::BITS - (2 * eta as u32).leading_zeros()) as usize
}

/// Power2Round (Algorithm 35)
///
/// 다항식 벡터 t의 각 계수를 상위 10비트(t1)와 하위 13비트(t0)로 분할합니다.
/// - t1 = ⌈t / 2^d⌉, t0 = t - t1 * 2^d
/// - t0 ∈ [-2^(d-1)+1, 2^(d-1)], d = 13
fn power2round_vec<const K: usize>(t: &PolyVec<K>) -> (PolyVec<K>, PolyVec<K>) {
    let mut t1 = PolyVec::<K>::new_zero();
    let mut t0 = PolyVec::<K>::new_zero();

    for i in 0..K {
        for j in 0..N {
            let a = t.vec[i].coeffs[j].0;

            // a1 = ⌈a / 2^13⌉ = (a + 2^12 - 1) >> 13 (상수-시간 올림 나눗셈)
            let a1 = (a + 4095) >> 13;
            let a0 = a - (a1 << 13); // a0 ∈ [-4095, 4096]

            // 음수 a0를 Fq 표현으로 상수-시간 변환 (부채널 방지)
            let is_neg = a0.ct_is_negative();
            let a0_fq = i32::ct_select(&(a0 + Q), &a0, is_neg);

            t1.vec[i].coeffs[j] = Fq::new(a1);
            t0.vec[i].coeffs[j] = Fq::new(a0_fq);
        }
    }

    (t1, t0)
}

//
// Algorithm 6: ML-DSA.KeyGen_internal(ξ)
//

/// Algorithm 6: ML-DSA.KeyGen_internal(ξ)
///
/// 32바이트 시드 ξ로부터 공개키와 비밀키 쌍을 결정론적으로 생성합니다.
pub(crate) fn keygen_internal<const K: usize, const L: usize, const ETA: i32>(
    xi: &[u8; 32],
) -> Result<(MLDSAPublicKey<K>, MLDSAPrivateKey<K, L, ETA>), MLDSAError> {
    // 1: (ρ, ρ', K) ← H(ξ || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
    let mut seed_input = [0u8; 34];
    seed_input[..32].copy_from_slice(xi);
    seed_input[32] = K as u8;
    seed_input[33] = L as u8;

    let mut shake = SHAKE256::new();
    shake.update(&seed_input);
    // let rho sfkjwenfoinf
    let expanded = shake.finalize(128)?;
    let ex_slice = expanded.as_slice();

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];
    rho.copy_from_slice(&ex_slice[0..32]);
    rho_prime.copy_from_slice(&ex_slice[32..96]);
    k_seed.copy_from_slice(&ex_slice[96..128]);

    // 3: A_hat ← ExpandA(ρ)
    let a_hat = expand_a::<K, L>(&rho)?;

    // 4: (s1, s2) ← ExpandS(ρ')
    let (mut s1, s2) = expand_s::<K, L, ETA>(&rho_prime)?;

    // 5: t ← INTT(A_hat ∘ NTT(s1)) + s2
    let s1_original = s1;
    s1.ntt();
    let mut t = a_hat.multiply_vector(&s1);
    t.intt();
    t = t.add(&s2);

    // 6: (t1, t0) ← Power2Round(t)
    let (t1, t0) = power2round_vec(&t);

    // 8: pk_bytes ← pkEncode(ρ, t1)
    // 9: tr ← H(pk_bytes, 64)
    //
    // FIPS 204에 따라 pkEncode 출력(ρ || SimpleBitPack(t1, 10))을 SHAKE256으로 해싱합니다.
    // pkEncode는 rho(32B) || 각 t1 다항식(320B씩 K개) 순서로 구성됩니다.
    // PK_LEN이 keygen_internal의 제네릭이 아니므로 인크리멘탈 해싱으로 처리합니다.
    let mut shake_tr = SHAKE256::new();
    shake_tr.update(&rho);
    for i in 0..K {
        let mut t1_poly_bytes = [0u8; 320]; // 32 * 10 = 320
        poly_simple_bit_pack_t1(&t1.vec[i], &mut t1_poly_bytes);
        shake_tr.update(&t1_poly_bytes);
    }
    let tr_buf = shake_tr.finalize(64)?;
    let mut tr = [0u8; 64];
    tr.copy_from_slice(tr_buf.as_slice());

    let pk = MLDSAPublicKey { rho, t1 };
    let sk = MLDSAPrivateKey {
        rho,
        k_seed,
        tr,
        s1: s1_original,
        s2,
        t0,
    };

    Ok((pk, sk))
}

//
// Algorithm 22/23: pkEncode / pkDecode
//

impl<const K: usize, const PK_LEN: usize> MLDSAPublicKeyTrait<K, PK_LEN> for MLDSAPublicKey<K> {
    /// Algorithm 22: pkEncode(ρ, t1)
    ///
    /// pk = ρ (32B) || SimpleBitPack(t1[0], 10) || ... || SimpleBitPack(t1[K-1], 10)
    /// t1 계수당 10비트, 다항식당 320바이트, 총 PK_LEN = 32 + 320K 바이트.
    fn pk_encode(&self) -> [u8; PK_LEN] {
        assert_eq!(
            PK_LEN,
            32 + 320 * K,
            "pkEncode: PK_LEN이 파라미터 셋과 일치하지 않습니다"
        ); // todo: 어썰션은 중요한데 이렇게 잡아주는게 좋을지... 다른 인/디코딩 함수도 동일

        let mut pk = [0u8; PK_LEN];

        // 1. ρ (32바이트)
        pk[..32].copy_from_slice(&self.rho);

        // 2. SimpleBitPack(t1[i], 10) (다항식당 320바이트)
        for i in 0..K {
            poly_simple_bit_pack_t1(&self.t1.vec[i], &mut pk[32 + i * 320..32 + (i + 1) * 320]);
        }

        pk
    }

    /// Algorithm 23: pkDecode(pk)
    ///
    /// pkEncode의 역연산. ρ와 t1을 복원합니다.
    fn pk_decode(pk: &[u8; PK_LEN]) -> Self {
        assert_eq!(
            PK_LEN,
            32 + 320 * K,
            "pkDecode: PK_LEN이 파라미터 셋과 일치하지 않습니다"
        );

        let mut rho = [0u8; SEED_LEN];
        rho.copy_from_slice(&pk[..32]);

        let mut t1 = PolyVec::<K>::new_zero();
        for i in 0..K {
            t1.vec[i] = poly_simple_bit_unpack_t1(&pk[32 + i * 320..32 + (i + 1) * 320]);
        }

        Self { rho, t1 }
    }
}

//
// Algorithm 24/25: skEncode / skDecode
//

impl<const K: usize, const L: usize, const ETA: i32, const SK_LEN: usize>
    MLDSAPrivateKeyTrait<K, L, SK_LEN> for MLDSAPrivateKey<K, L, ETA>
{
    /// Algorithm 24: skEncode(ρ, K, tr, s1, s2, t0)
    ///
    /// 비밀 키를 OS 잠금 메모리(SecureBuffer)에 직렬화합니다.
    ///
    /// 바이트 레이아웃:
    /// ```text
    /// ρ (32B) || K_seed (32B) || tr (64B)
    ///   || BitPack(s1[0..L-1], η, η)   (L × 32 × bitlen(2η) 바이트)
    ///   || BitPack(s2[0..K-1], η, η)   (K × 32 × bitlen(2η) 바이트)
    ///   || BitPack(t0[0..K-1], 4095, 4096) (K × 416 바이트)
    /// ```
    fn sk_encode(&self) -> Result<SecureBuffer, MLDSAError> {
        // ETA 비트 너비 및 각 섹션 크기 계산
        let eta_bw = eta_bit_width(ETA);
        let s1_len = L * 32 * eta_bw;
        let s2_len = K * 32 * eta_bw;
        let t0_len = K * 32 * 13;
        let expected_len = 32 + 32 + 64 + s1_len + s2_len + t0_len;

        debug_assert_eq!(
            SK_LEN, expected_len,
            "skEncode: SK_LEN이 파라미터 셋과 일치하지 않습니다"
        );

        // OS 레벨 메모리 잠금 + Drop 시 자동 소거
        let mut buf = SecureBuffer::new_owned(SK_LEN)?;
        let sk_bytes = buf.as_mut_slice();

        let mut off = 0;

        // 1. ρ (32바이트)
        sk_bytes[off..off + 32].copy_from_slice(&self.rho);
        off += 32;

        // 2. K_seed (32바이트)
        sk_bytes[off..off + 32].copy_from_slice(&self.k_seed);
        off += 32;

        // 3. tr (64바이트)
        sk_bytes[off..off + 64].copy_from_slice(&self.tr);
        off += 64;

        // 4. s1: BitPack(s1[i], η, η) — 계수 ∈ [-η, η]
        polyvec_bit_pack_eta::<L>(&self.s1, ETA, &mut sk_bytes[off..off + s1_len]);
        off += s1_len;

        // 5. s2: BitPack(s2[i], η, η) — 계수 ∈ [-η, η]
        polyvec_bit_pack_eta::<K>(&self.s2, ETA, &mut sk_bytes[off..off + s2_len]);
        off += s2_len;

        // 6. t0: BitPack(t0[i], 4095, 4096) — 계수 ∈ [-4095, 4096]
        polyvec_bit_pack_t0::<K>(&self.t0, &mut sk_bytes[off..off + t0_len]);

        Ok(buf)
    }

    /// Algorithm 25: skDecode(sk)
    ///
    /// skEncode의 역연산. SecureBuffer에서 ρ, K_seed, tr, s1, s2, t0를 복원합니다.
    fn sk_decode(sk: &SecureBuffer) -> Result<Self, MLDSAError> {
        let eta_bw = eta_bit_width(ETA);
        let s1_len = L * 32 * eta_bw;
        let s2_len = K * 32 * eta_bw;
        let t0_len = K * 32 * 13;
        let expected_len = 32 + 32 + 64 + s1_len + s2_len + t0_len;

        if sk.len() != expected_len {
            return Err(InvalidLength("skDecode: 잘못된 비밀 키 길이"));
        }

        // SK_LEN 상수와 런타임 길이 일치 검증 (파라미터 셋 오용 방지)
        if SK_LEN != expected_len {
            return Err(InvalidLength(
                "skDecode: SK_LEN이 파라미터 셋과 일치하지 않습니다",
            ));
        }

        let b = sk.as_slice();
        let mut off = 0;

        // 1. ρ (32바이트)
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&b[off..off + 32]);
        off += 32;

        // 2. K_seed (32바이트)
        let mut k_seed = [0u8; 32];
        k_seed.copy_from_slice(&b[off..off + 32]);
        off += 32;

        // 3. tr (64바이트)
        let mut tr = [0u8; 64];
        tr.copy_from_slice(&b[off..off + 64]);
        off += 64;

        // 4. s1: BitUnpack(s1[i], η, η)
        let s1: PolyVec<L> = polyvec_bit_unpack_eta(&b[off..off + s1_len], ETA);
        off += s1_len;

        // 5. s2: BitUnpack(s2[i], η, η)
        let s2: PolyVec<K> = polyvec_bit_unpack_eta(&b[off..off + s2_len], ETA);
        off += s2_len;

        // 6. t0: BitUnpack(t0[i], 4095, 4096)
        let t0: PolyVec<K> = polyvec_bit_unpack_t0(&b[off..off + t0_len]);

        Ok(Self {
            rho,
            k_seed,
            tr,
            s1,
            s2,
            t0,
        })
    }
}
