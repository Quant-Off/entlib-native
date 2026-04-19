use crate::Q;
use crate::Q_INV;
use entlib_native_constant_time::traits::{ConstantTimeIsNegative, ConstantTimeSelect};

/// 유한체 Z_q의 원소를 나타내는 구조체
#[derive(Clone, Copy, Debug, Default)]
pub struct Fq(pub i32);

impl Fq {
    /// 새로운 필드 요소를 생성합니다. (입력값은 [0, Q-1] 범위 내에 있어야 함)
    #[inline(always)]
    pub const fn new(val: i32) -> Self {
        Self(val)
    }

    /// 상수-시간 모듈러 덧셈
    pub fn add(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        // sum은 최대 2Q - 2 값을 가질 수 있습니다. Q를 빼서 범위를 맞춥니다.
        let sub = sum - Q;

        // sub가 음수(즉, sum < Q)이면 sum을 선택하고, 그렇지 않으면 sub를 선택합니다.
        let is_neg = sub.ct_is_negative();
        Self(i32::ct_select(&sum, &sub, is_neg))
    }

    /// 상수-시간 모듈러 뺄셈
    pub fn sub(self, other: Self) -> Self {
        let diff = self.0 - other.0;
        // diff는 음수가 될 수 있으므로 Q를 더한 값을 준비합니다.
        let add = diff + Q;

        // diff가 음수이면 Q를 더한 add를 선택하고, 그렇지 않으면 diff를 유지합니다.
        let is_neg = diff.ct_is_negative();
        Self(i32::ct_select(&add, &diff, is_neg))
    }

    /// 몽고메리 환원을 이용한 상수-시간 모듈러 곱셈
    ///
    /// a * b * R^(-1) mod Q 연산을 수행합니다. (여기서 R = 2^32)
    pub fn mul(self, other: Self) -> Self {
        let prod = (self.0 as i64) * (other.0 as i64);

        // t = (prod * Q_INV) mod 2^32
        let t = (prod as i32).wrapping_mul(Q_INV);
        // t_q = t * Q
        let t_q = (t as i64) * (Q as i64);

        // u = (prod - t_q) / 2^32
        let u = ((prod - t_q) >> 32) as i32;

        // u는 [-Q, Q-1] 범위에 있습니다. 음수인 경우 Q를 더해 보정합니다.
        let is_neg = u.ct_is_negative();
        let u_plus_q = u + Q;
        Self(i32::ct_select(&u_plus_q, &u, is_neg))
    }
}
