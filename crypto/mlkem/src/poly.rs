use crate::field::{add_q, sub_q};
use crate::ntt::{N, intt, multiply_ntts, ntt};

/// Polynomial in Z_q[X]/(X^256+1) with coefficients in [0, q-1].
#[derive(Clone, Copy)]
pub(crate) struct Poly(pub(crate) [i32; N]);

impl Poly {
    pub(crate) fn zero() -> Self {
        Self([0i32; N])
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.0[i] = add_q(self.0[i], other.0[i]);
        }
        r
    }

    pub(crate) fn sub(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.0[i] = sub_q(self.0[i], other.0[i]);
        }
        r
    }

    pub(crate) fn ntt(&mut self) {
        ntt(&mut self.0);
    }

    pub(crate) fn intt(&mut self) {
        intt(&mut self.0);
    }

    /// Pointwise multiply two NTT-domain polynomials.
    pub(crate) fn ntt_mul(&self, other: &Self) -> Self {
        Self(multiply_ntts(&self.0, &other.0))
    }
}

/// Vector of K polynomials.
#[derive(Clone, Copy)]
pub(crate) struct PolyVec<const K: usize>(pub(crate) [Poly; K]);

impl<const K: usize> PolyVec<K> {
    pub(crate) fn zero() -> Self {
        Self([Poly::zero(); K])
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..K {
            r.0[i] = self.0[i].add(&other.0[i]);
        }
        r
    }

    pub(crate) fn ntt(&mut self) {
        for p in self.0.iter_mut() {
            p.ntt();
        }
    }

    pub(crate) fn intt(&mut self) {
        for p in self.0.iter_mut() {
            p.intt();
        }
    }
}

/// K×K matrix of NTT-domain polynomials.
#[derive(Clone, Copy)]
pub(crate) struct PolyMatrix<const K: usize>(pub(crate) [[Poly; K]; K]);

impl<const K: usize> PolyMatrix<K> {
    pub(crate) fn zero() -> Self {
        Self([[Poly::zero(); K]; K])
    }

    /// Matrix-vector product: A_hat * s_hat (both in NTT domain).
    pub(crate) fn mul_vec(&self, v: &PolyVec<K>) -> PolyVec<K> {
        let mut r = PolyVec::<K>::zero();
        for i in 0..K {
            for j in 0..K {
                let prod = self.0[i][j].ntt_mul(&v.0[j]);
                r.0[i] = r.0[i].add(&prod);
            }
        }
        r
    }

    /// Transposed matrix-vector product: A_hat^T * r_hat.
    pub(crate) fn mul_vec_transposed(&self, v: &PolyVec<K>) -> PolyVec<K> {
        let mut r = PolyVec::<K>::zero();
        for i in 0..K {
            for j in 0..K {
                let prod = self.0[j][i].ntt_mul(&v.0[j]);
                r.0[i] = r.0[i].add(&prod);
            }
        }
        r
    }
}

/// Inner product of two NTT-domain vectors: sum of pointwise products.
pub(crate) fn inner_product<const K: usize>(a: &PolyVec<K>, b: &PolyVec<K>) -> Poly {
    let mut r = Poly::zero();
    for i in 0..K {
        let prod = a.0[i].ntt_mul(&b.0[i]);
        r = r.add(&prod);
    }
    r
}
