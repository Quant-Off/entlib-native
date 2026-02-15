//! 상수-시간(Constant-Time) 연산을 위한 통합 트레이트 및 구현체
//!
//! 이 모듈은 민감 데이터를 다룰 때 타이밍 공격(timing attack)을 방지하기 위해
//! CPU 분기(branch) 없이 비트 연산만으로 로직을 수행하는 메소드들을 제공합니다.
//!
//! # Author
//! Q. T. Felix
//!
//! # Security Warning
//! 이 코드는 `entlib-native`의 일부로, 컴파일러 최적화 레벨이나 타겟 아키텍처에 따라
//! 안전성이 달라질 수 있습니다. `x86_64` 및 `aarch64`에서는 인라인 어셈블리를 사용하여
//! 컴파일러 최적화를 원천 차단하며, 기타 아키텍처에서는 `core::hint::black_box`로 폴백합니다.
//! 최종 바이너리에 대한 어셈블리 검증이 권장됩니다.
//!
//! 이 모듈은 단순한 개념 증명(PoC) 기능을 가지지 않습니다.
//! 군사적 보안에 다다르기 위해 완벽한 상수 시간 기능을 구현해야 하고,
//! 이를 위해 다음의 기능을 구현 및 수행할 예정입니다.
//! - (O) 인라인 어셈블리 (`constant_time_asm` 모듈)
//! - (O) 어셈블리 검증 파이프라인
//! - 검증 라이브러리 교차 검증

pub trait ConstantTimeOps: Copy + Sized {
    /// 값이 0이면 참(All 1s), 아니면 거짓(0)을 반환합니다.
    fn ct_is_zero(self) -> Self;

    /// 값이 0이 아니면 참(All 1s), 0이면 거짓(0)을 반환합니다.
    fn ct_is_nonzero(self) -> Self;

    /// 값이 음수(MSB가 1)이면 참(All 1s), 아니면 거짓(0)을 반환합니다.
    /// Unsigned 타입의 경우 MSB가 1인지(큰 수인지)를 판별합니다.
    fn ct_is_negative(self) -> Self;

    /// 두 값이 같으면 참(All 1) 마스크를, 다르면 거짓(0) 마스크를 반환합니다.
    fn ct_eq(self, other: Self) -> Self;

    /// 두 값이 다르면 참(All 1) 마스크를, 같으면 거짓(0) 마스크를 반환합니다.
    fn ct_ne(self, other: Self) -> Self;

    /// 마스크에 따라 값을 선택합니다.
    ///
    /// # Logic
    /// `mask`가 참(`!0`)이면 `self`, 거짓(`0`)이면 `other`를 반환합니다.
    ///
    /// # Safety
    /// `mask`는 반드시 `ct_eq` 등의 결과로 생성된 유효한 마스크 값(`0` 또는 `!0`)이어야 합니다.
    /// 잘못된 마스크 값(예: `1`, `2`)이 입력될 경우 예측 불가능한 결과가 혼합되어 반환됩니다.
    fn ct_select(self, other: Self, mask: Self) -> Self;
}

macro_rules! impl_ct_ops {
    ($($t:ty),+) => {
        $(
            impl ConstantTimeOps for $t {
                #[inline(always)]
                fn ct_is_negative(self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_negative(self)
                }

                #[inline(always)]
                fn ct_is_nonzero(self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_nonzero(self)
                }

                #[inline(always)]
                fn ct_is_zero(self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_zero(self)
                }

                #[inline(always)]
                fn ct_eq(self, other: Self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_equal(self, other)
                }

                #[inline(always)]
                fn ct_ne(self, other: Self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_not_equal(self, other)
                }

                #[inline(always)]
                fn ct_select(self, other: Self, mask: Self) -> Self {
                    crate::constant_time_asm::CtPrimitive::ct_mux(self, other, mask)
                }
            }
        )+
    };
}

// 모든 정수 타입에 대해 구현 적용 (비트 수 자동 계산)
impl_ct_ops!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);
