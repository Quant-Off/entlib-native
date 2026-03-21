//! FIPS 204 Section 10: 비트 수준 인코딩 (Algorithms 16–21)
//!
//! 다항식 및 다항식 벡터의 비트 수준 패킹/언패킹 함수를 구현합니다.
//! 민감 데이터(s1, s2, t0 등)의 인코딩에는 상수-시간(Constant-time) 연산을 사용합니다.

use crate::Q;
use crate::field::Fq;
use crate::ntt::N;
use crate::poly::{Poly, PolyVec};
use entlib_native_constant_time::traits::{ConstantTimeIsNegative, ConstantTimeSelect};

//
// 내부 유틸리티
//

/// FIPS 204 bitlen(x) = ⌊log2(x)⌋ + 1 (x > 0), bitlen(0) = 0
#[inline(always)]
fn bitlen(n: u32) -> usize {
    (u32::BITS - n.leading_zeros()) as usize
}

/// Fq 양수 정규화 표현에서 부호 있는 i32로 상수-시간 변환
///
/// Fq 내부에서 음수 c는 (c + Q)로 저장됩니다.
/// `upper_bound`(= 범위 상한 b)를 기준으로:
/// - fq_val ≤ upper_bound → 비음수 → 반환값 = fq_val
/// - fq_val > upper_bound → 음수(Q가 더해진 상태) → 반환값 = fq_val − Q
#[inline(always)]
fn fq_to_signed_ct(fq_val: i32, upper_bound: i32) -> i32 {
    // (fq_val - upper_bound - 1) < 0  ↔  fq_val ≤ upper_bound (비음수 영역)
    let probe = fq_val.wrapping_sub(upper_bound).wrapping_sub(1);
    let is_nonneg = probe.ct_is_negative();
    let as_negative = fq_val.wrapping_sub(Q);
    i32::ct_select(&fq_val, &as_negative, is_nonneg)
}

/// 상수-시간 음수 보정: signed < 0 이면 signed + Q를 반환합니다.
#[inline(always)]
fn signed_to_fq_ct(signed: i32) -> i32 {
    let is_neg = signed.ct_is_negative();
    let with_q = signed.wrapping_add(Q);
    i32::ct_select(&with_q, &signed, is_neg)
}

//
// Algorithm 16: SimpleBitPack(w, b)
// Algorithm 18: SimpleBitUnpack(v, b)
//

/// Algorithm 16: SimpleBitPack(w, b)
///
/// 계수가 `[0, 2^b − 1]` 범위인 256-계수 다항식 `w`를 `b`비트/계수로 리틀-엔디언 패킹합니다.
///
/// - 출력 크기: 32 × b 바이트 (N=256이므로 256×b 비트 = 32×b 바이트)
///
/// FIPS 204 Algorithm 16 참조.
pub fn simple_bit_pack(w: &Poly, b: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * b, "simple_bit_pack: 출력 버퍼 크기 불일치");

    let mask: u64 = if b >= 64 { u64::MAX } else { (1u64 << b) - 1 };
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for coeff in &w.coeffs {
        buf |= (coeff.0 as u64 & mask) << bits;
        bits += b;
        while bits >= 8 {
            out[idx] = buf as u8;
            idx += 1;
            buf >>= 8;
            bits -= 8;
        }
    }
    // 256 × b 는 항상 8의 배수(256 = 2^8)이므로 bits == 0 이 보장됩니다.
}

/// Algorithm 18: SimpleBitUnpack(v, b)
///
/// `simple_bit_pack`의 역연산. `b`비트/계수로 패킹된 바이트 배열에서 다항식을 복원합니다.
///
/// FIPS 204 Algorithm 18 참조.
pub fn simple_bit_unpack(v: &[u8], b: usize) -> Poly {
    debug_assert_eq!(v.len(), 32 * b, "simple_bit_unpack: 입력 버퍼 크기 불일치");

    let mask: u64 = if b >= 64 { u64::MAX } else { (1u64 << b) - 1 };
    let mut poly = Poly::new_zero();
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for i in 0..N {
        while bits < b {
            buf |= (v[idx] as u64) << bits;
            idx += 1;
            bits += 8;
        }
        poly.coeffs[i] = Fq::new((buf & mask) as i32);
        buf >>= b;
        bits -= b;
    }

    poly
}

//
// Algorithm 17: BitPack(w, a, b)
// Algorithm 19: BitUnpack(v, a, b)
//

/// Algorithm 17: BitPack(w, a, b)
///
/// 계수가 `[−a, b]` 범위인 다항식 `w`를 `bitlen(a + b)`비트/계수로 패킹합니다.
/// 각 계수 c를 `(a + c)`로 인코딩합니다.
///
/// 계수는 Fq 형태로 입력됩니다 (음수 c는 c + Q로 표현됨).
/// 상수-시간 변환으로 타이밍 누출을 방지합니다.
///
/// 주요 사용처:
/// - s1, s2 (ETA=2 → 3비트, ETA=4 → 4비트)
/// - t0 (a=4095, b=4096 → 13비트)
/// - z  (a=γ1−1, b=γ1 → 18 또는 20비트)
///
/// FIPS 204 Algorithm 17 참조.
pub fn bit_pack(w: &Poly, a: i32, b: i32, out: &mut [u8]) {
    let bw = bitlen((a + b) as u32);
    debug_assert_eq!(out.len(), 32 * bw, "bit_pack: 출력 버퍼 크기 불일치");

    let mask: u64 = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for coeff in &w.coeffs {
        // 상수-시간으로 Fq → 부호 있는 정수 변환 (b가 비음수 범위 상한)
        let signed = fq_to_signed_ct(coeff.0, b);
        // encoded = a + signed ∈ [0, a+b]
        let encoded = (a as i64 + signed as i64) as u64;

        buf |= (encoded & mask) << bits;
        bits += bw;
        while bits >= 8 {
            out[idx] = buf as u8;
            idx += 1;
            buf >>= 8;
            bits -= 8;
        }
    }
}

/// Algorithm 19: BitUnpack(v, a, b)
///
/// `bit_pack`의 역연산. 인코딩된 값 `e = a + c`에서 계수 `c = e − a`를 복원합니다.
/// 음수 계수는 Fq 표현(c + Q)으로 변환됩니다.
///
/// FIPS 204 Algorithm 19 참조.
pub fn bit_unpack(v: &[u8], a: i32, b: i32) -> Poly {
    let bw = bitlen((a + b) as u32);
    debug_assert_eq!(v.len(), 32 * bw, "bit_unpack: 입력 버퍼 크기 불일치");

    let mask: u64 = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
    let mut poly = Poly::new_zero();
    let mut buf: u64 = 0;
    let mut bits: usize = 0;
    let mut idx: usize = 0;

    for i in 0..N {
        while bits < bw {
            buf |= (v[idx] as u64) << bits;
            idx += 1;
            bits += 8;
        }
        let encoded = (buf & mask) as i32;
        buf >>= bw;
        bits -= bw;

        // c = encoded − a; 음수이면 Fq 표현으로 상수-시간 변환
        let signed = encoded - a;
        poly.coeffs[i] = Fq::new(signed_to_fq_ct(signed));
    }

    poly
}

//
// Algorithm 20: HintBitPack(h)
// Algorithm 21: HintBitUnpack(y, ω)
//

/// Algorithm 20: HintBitPack(h)
///
/// 힌트 다항식 벡터 `h`를 압축 인코딩합니다.
/// 각 다항식의 계수는 0 또는 1이며, 1인 계수의 위치(인덱스)를 기록합니다.
///
/// 출력 형식 (총 ω + K 바이트):
/// - `out[0..ω]`: 1인 계수의 위치들 (다항식 순서대로 연속 기록, 나머지는 0)
/// - `out[ω..ω+K]`: i번째 원소 = 처음 i+1개 다항식까지의 1의 누적 개수
///
/// 전제: h 전체에서 0이 아닌 계수의 총 수 ≤ ω
///
/// FIPS 204 Algorithm 20 참조.
pub fn hint_bit_pack<const K: usize>(h: &PolyVec<K>, omega: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), omega + K, "hint_bit_pack: 출력 버퍼 크기 불일치");

    for b in out.iter_mut() {
        *b = 0;
    }

    let mut index: usize = 0;
    for i in 0..K {
        for j in 0..N {
            if h.vec[i].coeffs[j].0 != 0 {
                debug_assert!(index < omega, "hint_bit_pack: 1의 개수가 ω를 초과합니다");
                out[index] = j as u8;
                index += 1;
            }
        }
        // i번째 다항식까지의 누적 1의 개수
        out[omega + i] = index as u8;
    }
}

/// Algorithm 21: HintBitUnpack(y, ω)
///
/// `hint_bit_pack`의 역연산. 압축 인코딩된 힌트 바이트 배열에서 힌트 벡터를 복원합니다.
/// 인코딩이 유효하지 않으면 `None`을 반환합니다 (FIPS 204 Section 7.4의 유효성 조건 준수).
///
/// FIPS 204 Algorithm 21 참조.
pub fn hint_bit_unpack<const K: usize>(y: &[u8], omega: usize) -> Option<PolyVec<K>> {
    if y.len() != omega + K {
        return None;
    }

    let mut h = PolyVec::<K>::new_zero();
    let mut index: usize = 0;

    for i in 0..K {
        let limit = y[omega + i] as usize;

        // 단조 증가 및 ω 상한 검증
        if limit < index || limit > omega {
            return None;
        }

        let first = index;
        while index < limit {
            // 다항식 내에서 위치 인덱스는 엄격히 단조 증가해야 함 (중복/역순 방지)
            if index > first && y[index] <= y[index - 1] {
                return None;
            }
            h.vec[i].coeffs[y[index] as usize] = Fq::new(1);
            index += 1;
        }
    }

    // 사용되지 않은 패딩 영역(index..omega)은 0이어야 합니다 (인코딩 가변성 방지)
    if y[index..omega].iter().any(|&b| b != 0) {
        return None;
    }

    Some(h)
}

//
// 다항식 벡터 수준 래퍼 함수들
//

/// PolyVec<D>를 η 비트 패킹으로 직렬화합니다 (s1, s2 인코딩용).
///
/// 각 다항식은 `bitlen(2η)`비트/계수로 인코딩됩니다.
/// - η=2 → 3비트/계수, 96바이트/다항식
/// - η=4 → 4비트/계수, 128바이트/다항식
///
/// 출력 크기: D × 32 × bitlen(2η) 바이트
pub fn polyvec_bit_pack_eta<const D: usize>(vec: &PolyVec<D>, eta: i32, out: &mut [u8]) {
    let bw = bitlen((2 * eta) as u32);
    let bpp = 32 * bw; // bytes per poly
    for i in 0..D {
        bit_pack(&vec.vec[i], eta, eta, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

/// η 비트 언패킹으로 PolyVec<D>를 복원합니다 (s1, s2 디코딩용).
pub fn polyvec_bit_unpack_eta<const D: usize>(v: &[u8], eta: i32) -> PolyVec<D> {
    let bw = bitlen((2 * eta) as u32);
    let bpp = 32 * bw;
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * bpp..(i + 1) * bpp], eta, eta);
    }
    vec
}

/// PolyVec<D>를 t0 13비트 패킹으로 직렬화합니다.
///
/// t0 계수는 [-2^(d-1)+1, 2^(d-1)] = [-4095, 4096] 범위이며,
/// BitPack(t0, 2^(d-1)−1, 2^(d-1)) = BitPack(t0, 4095, 4096) 으로 인코딩됩니다.
///
/// 출력 크기: D × 416 바이트 (32 × 13)
pub fn polyvec_bit_pack_t0<const D: usize>(vec: &PolyVec<D>, out: &mut [u8]) {
    // d = 13, 2^(d-1) = 4096
    const A: i32 = (1 << 12) - 1; // 4095
    const B: i32 = 1 << 12; // 4096
    const BPP: usize = 32 * 13; // 416 bytes per poly
    for i in 0..D {
        bit_pack(&vec.vec[i], A, B, &mut out[i * BPP..(i + 1) * BPP]);
    }
}

/// t0 13비트 언패킹으로 PolyVec<D>를 복원합니다.
pub fn polyvec_bit_unpack_t0<const D: usize>(v: &[u8]) -> PolyVec<D> {
    const A: i32 = (1 << 12) - 1; // 4095
    const B: i32 = 1 << 12; // 4096
    const BPP: usize = 32 * 13; // 416 bytes per poly
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * BPP..(i + 1) * BPP], A, B);
    }
    vec
}

/// PolyVec<D>를 γ1 비트 패킹으로 직렬화합니다 (서명 z 인코딩용).
///
/// z 계수는 [−γ1+1, γ1] 범위이며, BitPack(z, γ1−1, γ1)으로 인코딩됩니다.
/// - γ1 = 2^17 → 18비트/계수, 576바이트/다항식
/// - γ1 = 2^19 → 20비트/계수, 640바이트/다항식
pub fn polyvec_bit_pack_z<const D: usize>(vec: &PolyVec<D>, gamma1: i32, out: &mut [u8]) {
    let a = gamma1 - 1;
    let bw = bitlen((a + gamma1) as u32);
    let bpp = 32 * bw;
    for i in 0..D {
        bit_pack(&vec.vec[i], a, gamma1, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

/// γ1 비트 언패킹으로 PolyVec<D>를 복원합니다 (서명 z 디코딩용).
pub fn polyvec_bit_unpack_z<const D: usize>(v: &[u8], gamma1: i32) -> PolyVec<D> {
    let a = gamma1 - 1;
    let bw = bitlen((a + gamma1) as u32);
    let bpp = 32 * bw;
    let mut vec = PolyVec::<D>::new_zero();
    for i in 0..D {
        vec.vec[i] = bit_unpack(&v[i * bpp..(i + 1) * bpp], a, gamma1);
    }
    vec
}

/// PolyVec<D>를 w1 비트 패킹으로 직렬화합니다 (분해 고차 비트 인코딩용).
///
/// w1 계수는 [0, (q−1)/(2γ2) − 1] 범위의 비음수입니다.
/// - γ2 = (q−1)/88 → 최대값 43 → bitlen(43) = 6비트/계수
/// - γ2 = (q−1)/32 → 최대값 15 → bitlen(15) = 4비트/계수
pub fn polyvec_simple_bit_pack_w1<const D: usize>(vec: &PolyVec<D>, gamma2: i32, out: &mut [u8]) {
    let max_coeff = (Q - 1) / (2 * gamma2) - 1;
    let bw = bitlen(max_coeff as u32);
    let bpp = 32 * bw;
    for i in 0..D {
        simple_bit_pack(&vec.vec[i], bw, &mut out[i * bpp..(i + 1) * bpp]);
    }
}

//
// 단일 다항식의 t1 패킹 (SimpleBitPack with b=10)
//

/// t1 다항식 하나를 SimpleBitPack(t1, 10)으로 직렬화합니다.
///
/// t1 계수는 [0, 2^10 − 1] = [0, 1023] 범위입니다.
/// 출력 크기: 320바이트 (32 × 10).
pub fn poly_simple_bit_pack_t1(w: &Poly, out: &mut [u8]) {
    simple_bit_pack(w, 10, out);
}

/// SimpleBitUnpack(v, 10)으로 t1 다항식을 복원합니다.
pub fn poly_simple_bit_unpack_t1(v: &[u8]) -> Poly {
    simple_bit_unpack(v, 10)
}

//
// 테스트
//

#[cfg(test)]
mod tests {
    // todo: 이거 옮기든가 축약하든가 해야되는데
    // 보기 안ㄴ좋음
    use super::*;
    use crate::poly::PolyVec;

    /// 계수 배열로 다항식 생성 헬퍼 (순환 적용)
    fn poly_from_slice(vals: &[i32]) -> Poly {
        let mut p = Poly::new_zero();
        for (i, c) in p.coeffs.iter_mut().enumerate() {
            *c = Fq::new(vals[i % vals.len()]);
        }
        p
    }

    //
    // bitlen
    //

    #[test]
    fn test_bitlen_fips204_values() {
        assert_eq!(bitlen(0), 0);
        assert_eq!(bitlen(1), 1);
        assert_eq!(bitlen(4), 3); // η=2: bitlen(2η) = bitlen(4) = 3
        assert_eq!(bitlen(8), 4); // η=4: bitlen(2η) = bitlen(8) = 4
        assert_eq!(bitlen(1023), 10); // t1: bitlen(2^10 - 1)
        assert_eq!(bitlen(8191), 13); // t0: bitlen(4095+4096)
        assert_eq!(bitlen(262143), 18); // z,γ1=2^17: bitlen(2γ1-1)
        assert_eq!(bitlen(1048575), 20); // z,γ1=2^19: bitlen(2γ1-1)
    }

    //
    // simple_bit_pack / simple_bit_unpack 왕복 테스트
    //

    #[test]
    fn test_simple_bit_pack_roundtrip_b10() {
        // t1: 계수 ∈ [0, 1023], b=10
        let vals: Vec<i32> = (0..256).map(|i| (i * 4) % 1024).collect();
        let poly = poly_from_slice(&vals);

        let mut buf = vec![0u8; 320]; // 32*10
        simple_bit_pack(&poly, 10, &mut buf);
        let recovered = simple_bit_unpack(&buf, 10);

        for i in 0..N {
            assert_eq!(poly.coeffs[i].0, recovered.coeffs[i].0, "계수 {i} 불일치");
        }
    }

    #[test]
    fn test_simple_bit_pack_roundtrip_b6() {
        // w1 (γ2=(q-1)/88): 계수 ∈ [0, 43], b=6
        let vals: Vec<i32> = (0..256).map(|i| i % 44).collect();
        let poly = poly_from_slice(&vals);

        let mut buf = vec![0u8; 192]; // 32*6
        simple_bit_pack(&poly, 6, &mut buf);
        let recovered = simple_bit_unpack(&buf, 6);

        for i in 0..N {
            assert_eq!(poly.coeffs[i].0, recovered.coeffs[i].0, "계수 {i} 불일치");
        }
    }

    #[test]
    fn test_simple_bit_pack_roundtrip_b4() {
        // w1 (γ2=(q-1)/32): 계수 ∈ [0, 15], b=4
        let vals: Vec<i32> = (0..256).map(|i| i % 16).collect();
        let poly = poly_from_slice(&vals);

        let mut buf = vec![0u8; 128]; // 32*4
        simple_bit_pack(&poly, 4, &mut buf);
        let recovered = simple_bit_unpack(&buf, 4);

        for i in 0..N {
            assert_eq!(poly.coeffs[i].0, recovered.coeffs[i].0, "계수 {i} 불일치");
        }
    }

    //
    // bit_pack / bit_unpack 왕복 테스트
    //

    /// Fq 표현으로 [-eta, eta] 범위의 계수를 가진 다항식 생성
    fn poly_eta(eta: i32) -> Poly {
        let mut p = Poly::new_zero();
        let range = 2 * eta + 1; // [-eta, eta] → range 가지 값
        for (i, c) in p.coeffs.iter_mut().enumerate() {
            let signed = (i as i32 % range) - eta; // -eta..=eta 순환
            let fq_val = if signed < 0 { signed + Q } else { signed };
            *c = Fq::new(fq_val);
        }
        p
    }

    #[test]
    fn test_bit_pack_roundtrip_eta2() {
        // s: 계수 ∈ [-2, 2], 3비트/계수, 96바이트
        let poly = poly_eta(2);
        let mut buf = vec![0u8; 96]; // 32*3
        bit_pack(&poly, 2, 2, &mut buf);
        let recovered = bit_unpack(&buf, 2, 2);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i].0, recovered.coeffs[i].0,
                "η=2 계수 {i} 불일치"
            );
        }
    }

    #[test]
    fn test_bit_pack_roundtrip_eta4() {
        // s: 계수 ∈ [-4, 4], 4비트/계수, 128바이트
        let poly = poly_eta(4);
        let mut buf = vec![0u8; 128]; // 32*4
        bit_pack(&poly, 4, 4, &mut buf);
        let recovered = bit_unpack(&buf, 4, 4);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i].0, recovered.coeffs[i].0,
                "η=4 계수 {i} 불일치"
            );
        }
    }

    #[test]
    fn test_bit_pack_roundtrip_t0() {
        // t0: 계수 ∈ [-4095, 4096], 13비트/계수, 416바이트
        // a=4095, b=4096
        let mut poly = Poly::new_zero();
        for (i, c) in poly.coeffs.iter_mut().enumerate() {
            // -4095 ~ +4096 범위를 순환
            let signed = (i as i32 % 8192) - 4095;
            let fq_val = if signed < 0 { signed + Q } else { signed };
            *c = Fq::new(fq_val);
        }

        let mut buf = vec![0u8; 416]; // 32*13
        bit_pack(&poly, 4095, 4096, &mut buf);
        let recovered = bit_unpack(&buf, 4095, 4096);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i].0, recovered.coeffs[i].0,
                "t0 계수 {i} 불일치"
            );
        }
    }

    #[test]
    fn test_bit_pack_roundtrip_z_gamma1_17() {
        // z: 계수 ∈ [-(γ1-1), γ1] = [-131071, 131072], 18비트, 576바이트
        let gamma1: i32 = 1 << 17; // 131072
        let a = gamma1 - 1;

        let mut poly = Poly::new_zero();
        for (i, c) in poly.coeffs.iter_mut().enumerate() {
            let signed = (i as i32 % (2 * gamma1)) - (gamma1 - 1);
            let fq_val = if signed < 0 { signed + Q } else { signed };
            *c = Fq::new(fq_val);
        }

        let bw = bitlen((a + gamma1) as u32); // 18
        let mut buf = vec![0u8; 32 * bw];
        bit_pack(&poly, a, gamma1, &mut buf);
        let recovered = bit_unpack(&buf, a, gamma1);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i].0, recovered.coeffs[i].0,
                "z(γ1=2^17) 계수 {i} 불일치"
            );
        }
    }

    #[test]
    fn test_bit_pack_roundtrip_z_gamma1_19() {
        // z: 계수 ∈ [-(γ1-1), γ1] = [-524287, 524288], 20비트, 640바이트
        let gamma1: i32 = 1 << 19; // 524288
        let a = gamma1 - 1;

        let mut poly = Poly::new_zero();
        for (i, c) in poly.coeffs.iter_mut().enumerate() {
            let signed = (i as i32 % (2 * 1024)) - 1023; // 단순화된 범위
            let fq_val = if signed < 0 { signed + Q } else { signed };
            *c = Fq::new(fq_val);
        }

        let bw = bitlen((a + gamma1) as u32); // 20
        let mut buf = vec![0u8; 32 * bw];
        bit_pack(&poly, a, gamma1, &mut buf);
        let recovered = bit_unpack(&buf, a, gamma1);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i].0, recovered.coeffs[i].0,
                "z(γ1=2^19) 계수 {i} 불일치"
            );
        }
    }

    //
    // hint_bit_pack / hint_bit_unpack 왕복 테스트
    //

    #[test]
    fn test_hint_bit_pack_roundtrip() {
        // K=4, ω=80 (ML-DSA-44)
        const K: usize = 4;
        const OMEGA: usize = 80;

        let mut h = PolyVec::<K>::new_zero();
        // 각 다항식에 몇 개의 힌트를 설정
        h.vec[0].coeffs[0] = Fq::new(1);
        h.vec[0].coeffs[5] = Fq::new(1);
        h.vec[1].coeffs[3] = Fq::new(1);
        h.vec[2].coeffs[200] = Fq::new(1);
        h.vec[3].coeffs[100] = Fq::new(1);
        h.vec[3].coeffs[255] = Fq::new(1);

        let mut buf = vec![0u8; OMEGA + K];
        hint_bit_pack(&h, OMEGA, &mut buf);

        let recovered = hint_bit_unpack::<K>(&buf, OMEGA).expect("hint_bit_unpack 실패");

        for i in 0..K {
            for j in 0..N {
                assert_eq!(
                    h.vec[i].coeffs[j].0, recovered.vec[i].coeffs[j].0,
                    "힌트 [{i}][{j}] 불일치"
                );
            }
        }
    }

    #[test]
    fn test_hint_bit_unpack_rejects_invalid_limit() {
        const K: usize = 4;
        const OMEGA: usize = 80;

        let mut buf = vec![0u8; OMEGA + K];
        // omega + 0 에 ω+1 = 81 을 써서 유효 범위 초과
        buf[OMEGA] = (OMEGA + 1) as u8;

        assert!(hint_bit_unpack::<K>(&buf, OMEGA).is_none());
    }

    #[test]
    fn test_hint_bit_unpack_rejects_nonmonotone() {
        const K: usize = 4;
        const OMEGA: usize = 80;

        let mut buf = vec![0u8; OMEGA + K];
        // 2개의 힌트를 역순으로 기록 (5, 3 → 단조 증가 위반)
        buf[0] = 5;
        buf[1] = 3;
        buf[OMEGA] = 2; // 첫 번째 다항식에 2개

        assert!(hint_bit_unpack::<K>(&buf, OMEGA).is_none());
    }

    #[test]
    fn test_hint_bit_unpack_rejects_nonzero_padding() {
        const K: usize = 4;
        const OMEGA: usize = 80;

        let mut buf = vec![0u8; OMEGA + K];
        // 힌트는 0개이지만 패딩 영역에 쓰레기 값
        buf[0] = 42; // 사용되지 않은 패딩

        // 모든 limit = 0 (힌트 없음)이므로 패딩 검사에서 실패해야 함
        assert!(hint_bit_unpack::<K>(&buf, OMEGA).is_none());
    }

    //
    // polyvec 래퍼 왕복 테스트
    //

    #[test]
    fn test_polyvec_eta2_roundtrip() {
        const L: usize = 4;
        let mut s1 = PolyVec::<L>::new_zero();
        for i in 0..L {
            s1.vec[i] = poly_eta(2);
        }

        let bw = bitlen(4); // 3
        let size = L * 32 * bw; // 4*96 = 384
        let mut buf = vec![0u8; size];
        polyvec_bit_pack_eta(&s1, 2, &mut buf);
        let recovered: PolyVec<L> = polyvec_bit_unpack_eta(&buf, 2);

        for i in 0..L {
            for j in 0..N {
                assert_eq!(s1.vec[i].coeffs[j].0, recovered.vec[i].coeffs[j].0);
            }
        }
    }

    #[test]
    fn test_polyvec_t0_roundtrip() {
        const K: usize = 4;
        let mut t0 = PolyVec::<K>::new_zero();
        for i in 0..K {
            for (j, c) in t0.vec[i].coeffs.iter_mut().enumerate() {
                let signed = (j as i32 % 8192) - 4095;
                let fq_val = if signed < 0 { signed + Q } else { signed };
                *c = Fq::new(fq_val);
            }
        }

        let size = K * 32 * 13; // 4*416 = 1664
        let mut buf = vec![0u8; size];
        polyvec_bit_pack_t0(&t0, &mut buf);
        let recovered: PolyVec<K> = polyvec_bit_unpack_t0(&buf);

        for i in 0..K {
            for j in 0..N {
                assert_eq!(t0.vec[i].coeffs[j].0, recovered.vec[i].coeffs[j].0);
            }
        }
    }

    #[test]
    fn test_poly_t1_roundtrip() {
        let vals: Vec<i32> = (0..256).map(|i| i % 1024).collect();
        let poly = poly_from_slice(&vals);
        let mut buf = vec![0u8; 320];
        poly_simple_bit_pack_t1(&poly, &mut buf);
        let recovered = poly_simple_bit_unpack_t1(&buf);
        for i in 0..N {
            assert_eq!(poly.coeffs[i].0, recovered.coeffs[i].0);
        }
    }
}
