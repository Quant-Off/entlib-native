use crate::MLDSAError::InternalError;
use crate::field::Fq;
use crate::ntt::N;
use crate::poly::{Poly, PolyMatrix, PolyVec};
use crate::{MLDSAError, Q};
use entlib_native_sha3::api::{SHAKE128, SHAKE256};

/// Algorithm 32: ExpandA(ρ)
///
/// 32바이트의 공개 시드 ρ로부터 k x l 크기의 다항식 행렬 A를 생성합니다.
/// 반환되는 행렬의 모든 다항식은 NTT 도메인에 위치합니다.
pub fn expand_a<const K: usize, const L: usize>(
    rho: &[u8; 32],
) -> Result<PolyMatrix<K, L>, MLDSAError> {
    let mut matrix = PolyMatrix::<K, L>::new_zero();

    // 명세에 따른 행렬 인덱싱: r (행, 0 to k-1), s (열, 0 to l-1)
    for r in 0..K {
        for s in 0..L {
            // ρ' = ρ || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = s as u8;
            seed[33] = r as u8;

            // RejNTTPoly(ρ') 호출 및 결과 할당
            matrix.rows[r][s] = rej_ntt_poly(&seed)?;
        }
    }

    Ok(matrix)
}

/// RejNTTPoly(ρ') 서브루틴
///
/// SHAKE128을 사용하여 시드로부터 유한체 Fq 상의 계수 256개를 거절 샘플링합니다.
fn rej_ntt_poly(seed: &[u8; 34]) -> Result<Poly, MLDSAError> {
    let mut shake = SHAKE128::new();
    shake.update(seed);

    // Q = 8380417, 23비트 최대값 = 8388607
    // 수용 확률(Acceptance Rate)은 8380417 / 8388608 ≈ 99.9% 임
    // 256개의 계수를 얻기 위해 최소 256 * 3 = 768 바이트가 필요하며
    // 거절 확률을 고려해 XOF에서 840 바이트를 한 번에 추출함(약 280회 샘플링 가능)
    let buf = shake.finalize(840)?;
    let data = buf.as_slice();

    let mut poly = Poly::new_zero();
    let mut count = 0;
    let mut i = 0;

    // 계수 256개를 모두 채울 때까지 반복
    while count < N && i + 3 <= data.len() {
        // Little-endian 방식의 3바이트 파싱
        let b0 = data[i] as u32;
        let b1 = data[i + 1] as u32;
        let b2 = data[i + 2] as u32;

        // FIPS 204 명세에 따른 23비트 마스킹 (세 번째 바이트의 최상위 비트 무시)
        let val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);

        // 거절 샘플링: 추출된 값이 Q 미만일 경우에만 다항식의 계수로 채택
        if val < Q as u32 {
            poly.coeffs[count] = Fq::new(val as i32);
            count += 1;
        }

        i += 3;
    }

    if count < N {
        // 극단적으로 운이 나빠 840바이트 내에서 256개를 채우지 못한 경우 방어 로직
        return Err(InternalError("거절 샘플링 중 SHAKE128 출력이 부족합니다!"));
    }

    Ok(poly)
}

/// Algorithm 33: ExpandS(ρ')
///
/// 64바이트의 비밀 시드 ρ'로부터 다항식 벡터 s1(크기 L)과 s2(크기 K)를 샘플링합니다.
/// 각 다항식의 계수는 [-ETA, ETA] 구간의 값을 가집니다.
///
/// # Generics
/// - `K`, `L`: ML-DSA 파라미터 (행렬 차원)
/// - `ETA`: 오차 분포 범위 (ML-DSA-44/87의 경우 2, ML-DSA-65의 경우 4)
pub fn expand_s<const K: usize, const L: usize, const ETA: i32>(
    rho_prime: &[u8; 64],
) -> Result<(PolyVec<L>, PolyVec<K>), MLDSAError> {
    let mut s1 = PolyVec::<L>::new_zero();
    let mut s2 = PolyVec::<K>::new_zero();

    // 1. s1 생성 (r from 0 to L - 1)
    for r in 0..L {
        // IntegerToBytes(r, 2)
        s1.vec[r] = rej_bounded_poly::<ETA>(rho_prime, r as u16)?;
    }

    // 2. s2 생성 (r from 0 to K - 1)
    for r in 0..K {
        // IntegerToBytes(r + L, 2)
        s2.vec[r] = rej_bounded_poly::<ETA>(rho_prime, (r + L) as u16)?;
    }

    Ok((s1, s2))
}

/// Algorithm 34: RejBoundedPoly(ρ', nonce)
///
/// SHAKE256을 사용하여 [-ETA, ETA] 범위 내의 계수 256개를 거절 샘플링합니다.
fn rej_bounded_poly<const ETA: i32>(rho_prime: &[u8; 64], nonce: u16) -> Result<Poly, MLDSAError> {
    // ρ' (64 bytes) || IntegerToBytes(nonce, 2)
    let mut seed = [0u8; 66];
    seed[..64].copy_from_slice(rho_prime);
    seed[64] = (nonce & 0xFF) as u8;
    seed[65] = (nonce >> 8) as u8;

    let mut shake = SHAKE256::new();
    shake.update(&seed);

    // 1바이트에서 2개의 4비트(nibble) 값을 추출
    // ETA = 2일 경우: 0~4 수용. 수용 확률 ≈ 31.25%. 256개 추출을 위해 약 819바이트 필요
    // ETA = 4일 경우: 0~8 수용. 수용 확률 ≈ 56.25%. 256개 추출을 위해 약 455바이트 필요
    // XOF 재호출(Re-squeeze)을 방지하기 위해 넉넉한 버퍼를 한 번에 할당함
    let buf_len = if ETA == 2 { 1024 } else { 768 };
    let buf = shake.finalize(buf_len)?; // 반환된 SecureBuffer는 스코프 종료 시 자동 소거됨
    let data = buf.as_slice();

    let mut poly = Poly::new_zero();
    let mut count = 0;
    let mut i = 0;

    while count < N && i < data.len() {
        let z = data[i];

        // z0 = z mod 16, z1 = floor(z / 16)
        let z0 = (z & 0x0F) as i32;
        let z1 = (z >> 4) as i32;

        // 첫 번째 니블 검사
        if z0 <= 2 * ETA {
            let mut val = ETA - z0; // [-ETA, ETA] 범위의 값
            // 음수일 경우 모듈러스 Q를 더해 정규화된 양수로 변환 (유한체 Fq의 표현 방식)
            if val < 0 {
                val += Q;
            }
            poly.coeffs[count] = Fq::new(val);
            count += 1;
        }

        // 두 번째 니블 검사 (count < N 확인 필수)
        if count < N && z1 <= 2 * ETA {
            let mut val = ETA - z1;
            if val < 0 {
                val += Q;
            }
            poly.coeffs[count] = Fq::new(val);
            count += 1;
        }

        i += 1;
    }

    if count < N {
        return Err(InternalError(
            "RejBoundedPoly 실행 중 SHAKE256 출력이 부족합니다!",
        ));
    }

    Ok(poly)
}
