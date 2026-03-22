use crate::field::Fq;
use crate::ntt::{N, intt, ntt};

/// FIPS 204 다항식 구조체
///
/// 256개의 Fq 계수를 가지며, 복사(Copy)가 가능하여 메모리 상에서
/// 안전하게 직렬화/역직렬화 및 소거(Zeroize)가 용이하도록 설계되었습니다.
#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [Fq; N],
}

impl Poly {
    /// 모든 계수가 0인 영다항식을 생성합니다.
    pub const fn new_zero() -> Self {
        Self {
            coeffs: [Fq::new(0); N],
        }
    }

    /// 두 다항식의 상수-시간 덧셈
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].add(other.coeffs[i]);
        }
        result
    }

    /// 두 다항식의 상수-시간 뺄셈
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].sub(other.coeffs[i]);
        }
        result
    }

    /// NTT 도메인 상에서 두 다항식의 점별 몽고메리 곱셈 (Point-wise Montgomery Multiplication)
    ///
    /// FIPS 204에서는 다항식이 256개의 1차 인수로 완전히 분해되므로,
    /// 나비 연산의 기본 단위(Basecase) 곱셈이 아닌 단순 계수별 곱셈만 수행합니다.
    pub fn pointwise_montgomery(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].mul(other.coeffs[i]);
        }
        result
    }
}

/// 차원이 D인 다항식 벡터 (비밀 키 s1, s2, 혹은 서명 요소 z 등에 사용)
/// ML-DSA 파라미터(k, l)에 따라 D 값은 4, 5, 6, 7, 8 중 하나가 됩니다.
#[derive(Clone, Copy)]
pub struct PolyVec<const D: usize> {
    pub vec: [Poly; D],
}

impl<const D: usize> PolyVec<D> {
    pub const fn new_zero() -> Self {
        Self {
            vec: [Poly::new_zero(); D],
        }
    }

    /// 벡터 내의 모든 다항식을 NTT 도메인으로 변환합니다 (제자리 연산).
    pub fn ntt(&mut self) {
        for i in 0..D {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    /// 벡터 내의 모든 다항식을 역방향 NTT를 통해 일반 도메인으로 복원합니다.
    pub fn intt(&mut self) {
        for i in 0..D {
            intt(&mut self.vec[i].coeffs);
        }
    }

    /// 벡터 간의 상수-시간 덧셈
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new_zero();
        for i in 0..D {
            result.vec[i] = self.vec[i].add(&other.vec[i]);
        }
        result
    }
}

/// K x L 크기의 다항식 행렬 (공개 행렬 A에 사용)
#[derive(Clone, Copy)]
pub struct PolyMatrix<const K: usize, const L: usize> {
    pub rows: [[Poly; L]; K],
}

impl<const K: usize, const L: usize> PolyMatrix<K, L> {
    pub const fn new_zero() -> Self {
        Self {
            rows: [[Poly::new_zero(); L]; K],
        }
    }

    /// FIPS 204 명세에 따른 행렬-벡터 곱셈 (t = A * s)
    ///
    /// 주의: 행렬 A와 벡터 s는 모두 NTT 도메인 상에 존재해야 합니다.
    /// 결과 벡터 t 또한 NTT 도메인의 다항식 벡터로 반환됩니다.
    pub fn multiply_vector(&self, s: &PolyVec<L>) -> PolyVec<K> {
        let mut t = PolyVec::<K>::new_zero();

        for i in 0..K {
            for j in 0..L {
                // A_{i,j} * s_j (점별 몽고메리 곱셈)
                let term = self.rows[i][j].pointwise_montgomery(&s.vec[j]);
                // t_i = t_i + (A_{i,j} * s_j)
                t.vec[i] = t.vec[i].add(&term);
            }
        }
        t
    }
}
