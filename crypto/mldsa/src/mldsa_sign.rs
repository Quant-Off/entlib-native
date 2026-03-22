//! FIPS 204 ML-DSA 서명 및 검증 내부 알고리즘 (Algorithms 5, 7)
//!
//! - Algorithm 5: ML-DSA.Sign_internal(sk, M', rnd)
//! - Algorithm 7: ML-DSA.Verify_internal(pk, M', σ)
//!
//! 지원 알고리즘:
//! - Algorithm 29: SampleInBall(ρ, τ)
//! - Algorithm 35: Decompose(r, α)  →  HighBits, LowBits
//! - Algorithm 36: ExpandMask(ρ'', κ)
//! - Algorithm 37: MakeHint(z, r, α)
//! - Algorithm 38: UseHint(h, r, α)

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::MLDSAError;
use crate::field::Fq;
use crate::mldsa_keys::{
    MLDSAPrivateKey, MLDSAPrivateKeyTrait, MLDSAPublicKey, MLDSAPublicKeyTrait,
};
use crate::ntt::N;
use crate::pack::{
    bit_unpack, hint_bit_pack, hint_bit_unpack, poly_simple_bit_pack_t1, polyvec_bit_pack_z,
    polyvec_bit_unpack_z, polyvec_simple_bit_pack_w1,
};
use crate::poly::{Poly, PolyVec};
use crate::sample::expand_a;
use crate::{D, Q};
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha3::api::SHAKE256;

//
// 내부 유틸리티
//

/// FIPS 204 bitlen(x) = ⌊log2(x)⌋ + 1  (x > 0), 0 (x = 0)
#[inline(always)]
fn bitlen(n: u32) -> usize {
    (u32::BITS - n.leading_zeros()) as usize
}

/// Fq 계수를 중심 부호 있는 정수로 변환 (타이밍-가변 — 공개 데이터 전용)
///
/// 거절 샘플링의 노름 검사처럼 결과가 공개(서명 재시도 여부)인 곳에서만 사용합니다.
#[inline(always)]
fn fq_to_signed(v: i32) -> i32 {
    if v > Q / 2 { v - Q } else { v }
}

/// 다항식 벡터의 무한 노름 (계수별 최대 절댓값)
fn inf_norm_vec<const D: usize>(v: &PolyVec<D>) -> i32 {
    let mut max = 0i32;
    for i in 0..D {
        for j in 0..N {
            let s = fq_to_signed(v.vec[i].coeffs[j].0).abs();
            if s > max {
                max = s;
            }
        }
    }
    max
}

/// PolyVec<D> 뺄셈: a − b
fn polyvec_sub<const D: usize>(a: &PolyVec<D>, b: &PolyVec<D>) -> PolyVec<D> {
    let mut r = PolyVec::<D>::new_zero();
    for i in 0..D {
        r.vec[i] = a.vec[i].sub(&b.vec[i]);
    }
    r
}

/// PolyVec<D> 부정: −v  (각 계수를 Q − v[i][j] 로 계산)
fn polyvec_neg<const D: usize>(v: &PolyVec<D>) -> PolyVec<D> {
    let mut r = PolyVec::<D>::new_zero();
    for i in 0..D {
        for j in 0..N {
            let c = v.vec[i].coeffs[j].0;
            r.vec[i].coeffs[j] = Fq::new(if c == 0 { 0 } else { Q - c });
        }
    }
    r
}

/// 단항식 c를 다항식 벡터의 각 원소와 NTT 점별 곱셈: c_hat ∘ v_hat
fn poly_mul_polyvec<const D: usize>(c: &Poly, v: &PolyVec<D>) -> PolyVec<D> {
    let mut r = PolyVec::<D>::new_zero();
    for i in 0..D {
        r.vec[i] = c.pointwise_montgomery(&v.vec[i]);
    }
    r
}

/// t1 * 2^D 스케일링 (NTT 도메인 진입 전 수행)
///
/// t1 계수 ∈ [0, 1023], 2^13 배 후 ∈ [0, 8380416] = [0, Q−1].
fn polyvec_scale_2d<const K: usize>(t1: &PolyVec<K>) -> PolyVec<K> {
    let mut r = PolyVec::<K>::new_zero();
    for i in 0..K {
        for j in 0..N {
            let v = t1.vec[i].coeffs[j].0 as i64;
            r.vec[i].coeffs[j] = Fq::new(((v << D) % Q as i64) as i32);
        }
    }
    r
}

/// 상수-시간 바이트 슬라이스 동치 비교
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

//
// Algorithm 35: Decompose(r, α) → (r1, r0)
//

/// Algorithm 35: Decompose(r, 2γ2)
///
/// r ∈ Z_q 를 r = r1 * 2γ2 + r0 로 분해합니다.
/// - r1 = HighBits(r) ∈ [0, (q−1)/(2γ2) − 1]
/// - r0 = LowBits(r) ∈ [−(γ2−1), γ2]  (부호 있는 정수로 반환)
/// - 특수: r+ − r0 = q − 1  →  r1 = 0, r0 = r0 − 1
///
/// 입력 r은 Fq 표현 [0, Q−1].
fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;
    let r_plus = r % Q; // 이미 [0, Q-1] 이므로 동일

    let mut r0 = r_plus % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }

    if r_plus - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

/// HighBits(w, 2γ2) — 다항식 벡터 버전
///
/// Fq 계수는 [0, Q-1] 표현이므로 decompose를 직접 적용합니다.
/// 반환값 r1 ∈ [0, (q−1)/(2γ2) − 1]는 Fq 표현 (= 비음수이므로 그대로 사용).
fn high_bits_vec<const D: usize>(w: &PolyVec<D>, gamma2: i32) -> PolyVec<D> {
    let mut r = PolyVec::<D>::new_zero();
    for i in 0..D {
        for j in 0..N {
            let (r1, _) = decompose(w.vec[i].coeffs[j].0, gamma2);
            r.vec[i].coeffs[j] = Fq::new(r1);
        }
    }
    r
}

/// LowBits(w, 2γ2) — 다항식 벡터 버전
///
/// 반환값 r0 ∈ [−(γ2−1), γ2]를 Fq 표현으로 반환 (음수는 + Q).
fn low_bits_vec<const D: usize>(w: &PolyVec<D>, gamma2: i32) -> PolyVec<D> {
    let mut r = PolyVec::<D>::new_zero();
    for i in 0..D {
        for j in 0..N {
            let (_, r0) = decompose(w.vec[i].coeffs[j].0, gamma2);
            let fq = if r0 < 0 { r0 + Q } else { r0 };
            r.vec[i].coeffs[j] = Fq::new(fq);
        }
    }
    r
}

//
// Algorithm 37: MakeHint(z, r, α)
// Algorithm 38: UseHint(h, r, α)
//

/// Algorithm 37: MakeHint(−ct0, w − cs2 + ct0, 2γ2)  — 계수 단위
///
/// h = 1  if HighBits(r + z, α) ≠ HighBits(r, α),  else 0
#[inline(always)]
fn make_hint_coeff(z_fq: i32, r_fq: i32, gamma2: i32) -> i32 {
    let (r1, _) = decompose(r_fq, gamma2);
    // (r + z) mod q
    let rz = ((r_fq as i64 + z_fq as i64).rem_euclid(Q as i64)) as i32;
    let (v1, _) = decompose(rz, gamma2);
    if r1 != v1 { 1 } else { 0 }
}

/// MakeHint 다항식 벡터 버전 — (h, count) 반환
fn make_hint_vec<const K: usize>(
    z: &PolyVec<K>,
    r: &PolyVec<K>,
    gamma2: i32,
) -> (PolyVec<K>, usize) {
    let mut h = PolyVec::<K>::new_zero();
    let mut count = 0usize;
    for i in 0..K {
        for j in 0..N {
            let bit = make_hint_coeff(z.vec[i].coeffs[j].0, r.vec[i].coeffs[j].0, gamma2);
            h.vec[i].coeffs[j] = Fq::new(bit);
            count += bit as usize;
        }
    }
    (h, count)
}

/// Algorithm 38: UseHint(h, r, 2γ2) — 계수 단위
#[inline(always)]
fn use_hint_coeff(h: i32, r_fq: i32, gamma2: i32) -> i32 {
    let m = (Q - 1) / (2 * gamma2); // 최대 HighBits 값 + 1
    let (r1, r0) = decompose(r_fq, gamma2);
    if h == 1 {
        if r0 > 0 {
            (r1 + 1).rem_euclid(m)
        } else {
            (r1 - 1).rem_euclid(m)
        }
    } else {
        r1
    }
}

/// UseHint 다항식 벡터 버전
fn use_hint_vec<const K: usize>(h: &PolyVec<K>, r: &PolyVec<K>, gamma2: i32) -> PolyVec<K> {
    let mut w1 = PolyVec::<K>::new_zero();
    for i in 0..K {
        for j in 0..N {
            let bit = h.vec[i].coeffs[j].0;
            let v = use_hint_coeff(bit, r.vec[i].coeffs[j].0, gamma2);
            w1.vec[i].coeffs[j] = Fq::new(v);
        }
    }
    w1
}

//
// Algorithm 29: SampleInBall(ρ, τ)
//

/// Algorithm 29: SampleInBall(ρ, τ)
///
/// c~ (c_tilde) 로부터 SHAKE256 XOF를 통해 정확히 τ 개의 ±1 계수를 가진
/// 다항식 c를 샘플링합니다.
///
/// 알고리즘:
/// 1. 첫 8바이트를 부호 비트(signs, 64-bit little-endian)로 사용
/// 2. 이후 τ번: j ≤ i가 될 때까지 1바이트씩 샘플링 → swap c[i] ↔ c[j] → c[j] = ±1
fn sample_in_ball(c_tilde: &[u8], tau: usize) -> Result<Poly, MLDSAError> {
    // 넉넉한 버퍼를 한 번에 추출: 8 (부호) + 256 * 3 (거절 여유)
    let buf_len = 8 + 256 + tau * 8;

    let mut shake = SHAKE256::new();
    shake.update(c_tilde);
    let buf = shake.finalize(buf_len)?;
    let data = buf.as_slice();

    // 부호 비트 (64-bit little-endian)
    let mut signs: u64 = 0;
    for (k, &byte) in data.iter().enumerate().take(8) {
        signs |= (byte as u64) << (8 * k);
    }

    let mut c = Poly::new_zero();
    let mut idx = 8usize; // XOF 스트림 소비 위치

    for i in (N - tau)..N {
        // j ≤ i가 될 때까지 바이트 소비
        let j = loop {
            if idx >= data.len() {
                return Err(MLDSAError::InternalError(
                    "SampleInBall: SHAKE256 출력 소진 (극히 드문 경우)",
                ));
            }
            let candidate = data[idx] as usize;
            idx += 1;
            if candidate <= i {
                break candidate;
            }
        };

        // c[i] = c[j], c[j] = (−1)^{signs bit}
        c.coeffs[i] = c.coeffs[j];
        let sign_bit = (signs & 1) as i32; // 0 또는 1
        // 1 − 2*sign_bit: sign=0 → +1, sign=1 → −1 (Fq에서 음수는 Q−1)
        c.coeffs[j] = if sign_bit == 0 {
            Fq::new(1)
        } else {
            Fq::new(Q - 1) // −1 mod Q
        };
        signs >>= 1;
    }

    Ok(c)
}

//
// Algorithm 36: ExpandMask(ρ'', κ)
//

/// Algorithm 36: ExpandMask(ρ'', κ, γ1) → PolyVec<L>
///
/// 64바이트 시드 ρ''와 카운터 κ로부터 L개의 다항식 벡터 y를 생성합니다.
/// y[i] 계수 ∈ [−(γ1−1), γ1].
fn expand_mask<const L: usize>(
    rho_pp: &[u8; 64],
    kappa: u16,
    gamma1: i32,
) -> Result<PolyVec<L>, MLDSAError> {
    // FIPS 204 §2.1: 계수 범위 [−(γ1−1), γ1] → 2γ1 개 값 → bitlen(2γ1−1) 비트/계수
    // (γ1이 2의 거듭제곱이면 bitlen(γ1−1)+1 = bitlen(2γ1−1))
    let c = bitlen((2 * gamma1 - 1) as u32);
    let bpp = 32 * c; // bytes per polynomial

    let mut y = PolyVec::<L>::new_zero();

    for i in 0..L {
        let nonce = kappa + i as u16;
        // 시드 = ρ'' (64B) || IntegerToBytes(nonce, 2)
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_pp);
        seed[64] = (nonce & 0xFF) as u8;
        seed[65] = (nonce >> 8) as u8;

        let mut shake = SHAKE256::new();
        shake.update(&seed);
        let buf = shake.finalize(bpp)?;

        // BitUnpack(buf, γ1−1, γ1) → 계수 ∈ [−(γ1−1), γ1]
        y.vec[i] = bit_unpack(buf.as_slice(), gamma1 - 1, gamma1);
    }

    Ok(y)
}

//
// Algorithm 26/27: SigEncode / SigDecode
//

/// Algorithm 26: sigEncode(c~, z, h, γ1, ω) → σ
///
/// 서명 인코딩:
/// ```text
/// σ = c~ (LAMBDA/4 B) || BitPack(z, γ1−1, γ1) (L×bpp B) || HintBitPack(h) (ω+K B)
/// ```
fn sig_encode<const K: usize, const L: usize, const LAMBDA: usize, const SIG_LEN: usize>(
    c_tilde: &[u8], // LAMBDA/4 바이트
    z: &PolyVec<L>,
    h: &PolyVec<K>,
    gamma1: i32,
    omega: usize,
) -> Result<[u8; SIG_LEN], MLDSAError> {
    let c_tilde_len = LAMBDA / 4;
    let z_bw = bitlen((2 * gamma1 - 1) as u32);
    let z_bpp = 32 * z_bw;
    let z_total = L * z_bpp;
    let h_total = omega + K;

    debug_assert_eq!(
        SIG_LEN,
        c_tilde_len + z_total + h_total,
        "sigEncode: SIG_LEN이 파라미터와 일치하지 않습니다"
    );

    let mut sig = [0u8; SIG_LEN];
    let mut off = 0;

    // 1. c~
    sig[off..off + c_tilde_len].copy_from_slice(c_tilde);
    off += c_tilde_len;

    // 2. BitPack(z[i], γ1−1, γ1)
    polyvec_bit_pack_z::<L>(z, gamma1, &mut sig[off..off + z_total]);
    off += z_total;

    // 3. HintBitPack(h)
    hint_bit_pack::<K>(h, omega, &mut sig[off..off + h_total]);

    Ok(sig)
}

/// Algorithm 27: sigDecode(σ, γ1, ω) → Option<(c_tilde, z, h)>
///
/// 서명 디코딩. 유효하지 않은 인코딩이면 `None` 반환.
fn sig_decode<const K: usize, const L: usize, const LAMBDA: usize>(
    sig: &[u8],
    gamma1: i32,
    omega: usize,
) -> Option<(Vec<u8>, PolyVec<L>, PolyVec<K>)> {
    let c_tilde_len = LAMBDA / 4;
    let z_bw = bitlen((2 * gamma1 - 1) as u32);
    let z_bpp = 32 * z_bw;
    let z_total = L * z_bpp;
    let h_total = omega + K;

    if sig.len() != c_tilde_len + z_total + h_total {
        return None;
    }

    let mut off = 0;

    // c~
    let c_tilde = sig[off..off + c_tilde_len].to_vec();
    off += c_tilde_len;

    // z: BitUnpack(bytes, γ1−1, γ1)
    let z: PolyVec<L> = polyvec_bit_unpack_z(&sig[off..off + z_total], gamma1);
    off += z_total;

    // h: HintBitUnpack 유효성 검증 포함
    let h: PolyVec<K> = hint_bit_unpack(&sig[off..off + h_total], omega)?;

    Some((c_tilde, z, h))
}

//
// Algorithm 28: w1Encode(w1)
//

/// Algorithm 28: w1Encode(w1, γ2) → bytes
///
/// w1 계수 ∈ [0, (q−1)/(2γ2) − 1]를 비트 팩킹합니다.
fn w1_encode<const K: usize>(w1: &PolyVec<K>, gamma2: i32) -> Vec<u8> {
    let max_coeff = (Q - 1) / (2 * gamma2) - 1;
    let bw = bitlen(max_coeff as u32);
    let bpp = 32 * bw;
    let total = K * bpp;
    let mut out = vec![0u8; total];
    polyvec_simple_bit_pack_w1::<K>(w1, gamma2, &mut out);
    out
}

//
// Algorithm 5: ML-DSA.Sign_internal
//

/// Algorithm 5: ML-DSA.Sign_internal(sk, M', rnd)
///
/// 거절 샘플링 기반 서명을 생성합니다. `rnd`가 [0u8; 32]이면
/// 순수 결정론적(deterministic) 서명, 그 외에는 헤지드(hedged) 서명입니다.
///
/// # 파라미터
/// - `K`, `L`: 행렬 차원
/// - `ETA`: 비밀 키 계수 범위 η
/// - `GAMMA1`, `GAMMA2`: Decompose 범위 파라미터
/// - `BETA`: β = τ · η (거절 임계값)
/// - `OMEGA`: 힌트 최대 1의 개수
/// - `LAMBDA`: 충돌 강도 (비트), c~ = LAMBDA/4 바이트
/// - `TAU`: 챌린지 다항식 ±1 계수 수
/// - `SK_LEN`, `SIG_LEN`: 직렬화 크기
pub(crate) fn sign_internal_impl<
    const K: usize,
    const L: usize,
    const ETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const BETA: i32,
    const OMEGA: usize,
    const LAMBDA: usize,
    const TAU: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    sk_buf: &SecureBuffer,
    m_prime: &[u8],
    rnd: &[u8; 32],
) -> Result<SecureBuffer, MLDSAError> {
    // 1: (ρ, K, tr, s1, s2, t0) ← skDecode(sk)
    let sk = <MLDSAPrivateKey<K, L, ETA> as MLDSAPrivateKeyTrait<K, L, SK_LEN>>::sk_decode(sk_buf)?;

    // 2: s1_hat, s2_hat, t0_hat ← NTT(s1), NTT(s2), NTT(t0)
    let mut s1_hat = sk.s1;
    s1_hat.ntt();
    let mut s2_hat = sk.s2;
    s2_hat.ntt();
    let mut t0_hat = sk.t0;
    t0_hat.ntt();

    // 3: A_hat ← ExpandA(ρ)
    let a_hat = expand_a::<K, L>(&sk.rho)?;

    // 4: μ ← H(tr || M', 64)
    let mut shake_mu = SHAKE256::new();
    shake_mu.update(&sk.tr);
    shake_mu.update(m_prime);
    let mu_buf = shake_mu.finalize(64)?;
    let mut mu = [0u8; 64];
    mu.copy_from_slice(mu_buf.as_slice());

    // 5: ρ'' ← H(K || rnd || μ, 64)
    let mut shake_rho_pp = SHAKE256::new();
    shake_rho_pp.update(&sk.k_seed);
    shake_rho_pp.update(rnd);
    shake_rho_pp.update(&mu);
    let rho_pp_buf = shake_rho_pp.finalize(64)?;
    let mut rho_pp = [0u8; 64];
    rho_pp.copy_from_slice(rho_pp_buf.as_slice());

    // 6: κ ← 0 (카운터; 각 반복마다 L씩 증가)
    let mut kappa: u16 = 0;

    // 최대 반복 횟수 (확률적으로 극히 드물게 초과)
    const MAX_ITER: usize = 1000;

    for _ in 0..MAX_ITER {
        // a: y ← ExpandMask(ρ'', κ)
        let y = expand_mask::<L>(&rho_pp, kappa, GAMMA1)?;

        // b: w ← INTT(A_hat ∘ NTT(y))
        let mut y_hat = y;
        y_hat.ntt();
        let mut w = a_hat.multiply_vector(&y_hat);
        w.intt();

        // c: w1 ← HighBits(w, 2γ2)
        let w1 = high_bits_vec::<K>(&w, GAMMA2);

        // d: c~ ← H(μ || w1Encode(w1), LAMBDA/4 바이트)
        let c_tilde_len = LAMBDA / 4;
        let w1_bytes = w1_encode::<K>(&w1, GAMMA2);
        let mut shake_c = SHAKE256::new();
        shake_c.update(&mu);
        shake_c.update(&w1_bytes);
        let c_tilde_buf = shake_c.finalize(c_tilde_len)?;
        let c_tilde = c_tilde_buf.as_slice();

        // e/f: c ← SampleInBall(c~, τ), c_hat ← NTT(c)
        let mut c_hat_poly = sample_in_ball(c_tilde, TAU)?;
        c_hat_poly_ntt(&mut c_hat_poly);
        let c_hat = &c_hat_poly;

        // g/h: z ← y + INTT(c_hat ∘ s1_hat)
        let mut cs1 = poly_mul_polyvec::<L>(c_hat, &s1_hat);
        cs1.intt();
        let z = y.add(&cs1);

        // i/j: r0 ← LowBits(w − INTT(c_hat ∘ s2_hat), 2γ2)
        let mut cs2 = poly_mul_polyvec::<K>(c_hat, &s2_hat);
        cs2.intt();
        let w_minus_cs2 = polyvec_sub::<K>(&w, &cs2);
        let r0 = low_bits_vec::<K>(&w_minus_cs2, GAMMA2);

        // k: 거절 조건 1 — ||z||∞ ≥ γ1 − β  또는  ||r0||∞ ≥ γ2 − β
        if inf_norm_vec::<L>(&z) >= GAMMA1 - BETA || inf_norm_vec::<K>(&r0) >= GAMMA2 - BETA {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        // l: ct0 ← INTT(c_hat ∘ t0_hat)
        let mut ct0 = poly_mul_polyvec::<K>(c_hat, &t0_hat);
        ct0.intt();

        // m: h ← MakeHint(−ct0, w − cs2 + ct0, 2γ2)
        let neg_ct0 = polyvec_neg::<K>(&ct0);
        let w_minus_cs2_plus_ct0 = w_minus_cs2.add(&ct0);
        let (h, h_count) = make_hint_vec::<K>(&neg_ct0, &w_minus_cs2_plus_ct0, GAMMA2);

        // n: 거절 조건 2 — ||ct0||∞ ≥ γ2  또는  Σh > ω
        if inf_norm_vec::<K>(&ct0) >= GAMMA2 || h_count > OMEGA {
            kappa = kappa.wrapping_add(L as u16);
            continue;
        }

        // o: σ ← sigEncode(c~, z, h)
        let sig_arr = sig_encode::<K, L, LAMBDA, SIG_LEN>(c_tilde, &z, &h, GAMMA1, OMEGA)?;
        let mut sig_buf = SecureBuffer::new_owned(SIG_LEN)?;
        sig_buf.as_mut_slice().copy_from_slice(&sig_arr);
        return Ok(sig_buf);
    }

    Err(MLDSAError::SigningFailed)
}

//
// Algorithm 7: ML-DSA.Verify_internal
//

/// Algorithm 7: ML-DSA.Verify_internal(pk, M', σ)
///
/// # 검증 절차
/// 1. pkDecode(pk) → (ρ, t1)
/// 2. sigDecode(σ) → (c~, z, h)  — 실패 시 false 반환
/// 3. A_hat ← ExpandA(ρ)
/// 4. tr ← H(pk, 64);  μ ← H(tr || M', 64)
/// 5. c ← SampleInBall(c~, τ);  c_hat ← NTT(c)
/// 6. w'_approx ← INTT(A_hat ∘ NTT(z) − c_hat ∘ NTT(t1 · 2^d))
/// 7. w1' ← UseHint(h, w'_approx, 2γ2)
/// 8. c~' ← H(μ || w1Encode(w1'), LAMBDA/4 B)
/// 9. 검증: ||z||∞ < γ1 − β  AND  c~ = c~'
pub(crate) fn verify_internal_impl<
    const K: usize,
    const L: usize,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const BETA: i32,
    const OMEGA: usize,
    const LAMBDA: usize,
    const TAU: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    pk_bytes: &[u8],
    m_prime: &[u8],
    sig: &[u8],
) -> Result<bool, MLDSAError> {
    // 길이 사전 검사
    if pk_bytes.len() != PK_LEN || sig.len() != SIG_LEN {
        return Ok(false);
    }

    // 1: (ρ, t1) ← pkDecode(pk)
    let pk_arr: &[u8; PK_LEN] = pk_bytes
        .try_into()
        .map_err(|_| MLDSAError::InvalidLength("verify: pk 길이 변환 실패"))?;
    let pk = <MLDSAPublicKey<K> as MLDSAPublicKeyTrait<K, PK_LEN>>::pk_decode(pk_arr);

    // 2: (c~, z, h) ← sigDecode(σ)
    let (c_tilde, z, h) = match sig_decode::<K, L, LAMBDA>(sig, GAMMA1, OMEGA) {
        Some(v) => v,
        None => return Ok(false),
    };

    // 3: A_hat ← ExpandA(ρ)
    let a_hat = expand_a::<K, L>(&pk.rho)?;

    // 4: tr ← H(pk_bytes, 64)
    let mut shake_tr = SHAKE256::new();
    shake_tr.update(&pk.rho);
    for i in 0..K {
        let mut t1_poly_bytes = [0u8; 320];
        poly_simple_bit_pack_t1(&pk.t1.vec[i], &mut t1_poly_bytes);
        shake_tr.update(&t1_poly_bytes);
    }
    let tr_buf = shake_tr.finalize(64)?;
    let mut tr = [0u8; 64];
    tr.copy_from_slice(tr_buf.as_slice());

    // μ ← H(tr || M', 64)
    let mut shake_mu = SHAKE256::new();
    shake_mu.update(&tr);
    shake_mu.update(m_prime);
    let mu_buf = shake_mu.finalize(64)?;
    let mut mu = [0u8; 64];
    mu.copy_from_slice(mu_buf.as_slice());

    // 5: c ← SampleInBall(c~, τ), c_hat ← NTT(c)
    let mut c_hat_poly = sample_in_ball(&c_tilde, TAU)?;
    c_hat_poly_ntt(&mut c_hat_poly);
    let c_hat = &c_hat_poly;

    // 6: w'_approx ← INTT(A_hat ∘ NTT(z) − c_hat ∘ NTT(t1 · 2^d))
    let mut z_hat = z;
    z_hat.ntt();
    let az_hat = a_hat.multiply_vector(&z_hat); // A_hat ∘ NTT(z) in NTT domain

    let t1_scaled = polyvec_scale_2d::<K>(&pk.t1);
    let mut t1_hat = t1_scaled;
    t1_hat.ntt();
    let ct1_hat = poly_mul_polyvec::<K>(c_hat, &t1_hat); // c_hat ∘ NTT(t1·2^d)

    let mut w_approx_hat = polyvec_sub::<K>(&az_hat, &ct1_hat);
    w_approx_hat.intt(); // INTT(...)

    // 7: w1' ← UseHint(h, w'_approx, 2γ2)
    let w1_prime = use_hint_vec::<K>(&h, &w_approx_hat, GAMMA2);

    // 9a: ||z||∞ < γ1 − β
    // z는 sig_decode에서 Fq 표현으로 복원됐으며, z_hat = z 복사 후 z는 유효.
    if inf_norm_vec::<L>(&z) >= GAMMA1 - BETA {
        return Ok(false);
    }

    // 8: c~' ← H(μ || w1Encode(w1'), LAMBDA/4 B)
    let c_tilde_len = LAMBDA / 4;
    let w1_bytes = w1_encode::<K>(&w1_prime, GAMMA2);
    let mut shake_c = SHAKE256::new();
    shake_c.update(&mu);
    shake_c.update(&w1_bytes);
    let c_tilde_prime_buf = shake_c.finalize(c_tilde_len)?;

    // 9b: 상수-시간 비교 c~ == c~'
    Ok(ct_eq_bytes(&c_tilde, c_tilde_prime_buf.as_slice()))
}

//
// NTT 헬퍼 (단일 다항식)
//

/// 단일 다항식에 NTT 변환 적용 (제자리 연산)
#[inline(always)]
fn c_hat_poly_ntt(c: &mut Poly) {
    use crate::ntt::ntt as ntt_fn;
    ntt_fn(&mut c.coeffs);
}
