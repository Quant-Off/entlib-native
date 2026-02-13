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
//! 안전성이 달라질 수 있습니다. `core::hint::black_box`를 사용하여 최적화를 방지하고 있으나,
//! 최종 바이너리에 대한 어셈블리 검증이 권장됩니다.

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
                    // 아키텍처 의존성 해결: 컴파일 타임에 비트 수 계산
                    const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;

                    // 최적화 방지
                    let val = core::hint::black_box(self);

                    // MSB 추출
                    let msb = val >> (BITS - 1);

                    // Signed 타입의 산술 시프트 부호 확장을 방지하기 위해 & 1 적용
                    // 0 또는 1로 정규화 후 부정 연산
                    (msb & 1).wrapping_neg()
                }

                #[inline(always)]
                fn ct_is_nonzero(self) -> Self {
                    const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;
                    let val = core::hint::black_box(self);

                    // (x | -x)의 MSB는 x가 0일 때만 0이고, 그 외에는 항상 1
                    let or_neg = val | val.wrapping_neg();
                    let msb = or_neg >> (BITS - 1);

                    (msb & 1).wrapping_neg()
                }

                #[inline(always)]
                fn ct_is_zero(self) -> Self {
                    // ct_is_nonzero의 결과를 반전(NOT)
                    !self.ct_is_nonzero()
                }

                #[inline(always)]
                fn ct_eq(self, other: Self) -> Self {
                    const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;
                    let a = core::hint::black_box(self);
                    let b = core::hint::black_box(other);

                    // XOR로 차이 계산
                    let diff = a ^ b;

                    // 0이 아닌 비트가 하나라도 있으면 MSB를 1로 만듦
                    let diff_or_neg = diff | diff.wrapping_neg();
                    let non_zero_bit = (diff_or_neg >> (BITS - 1)) & 1;

                    // 1(다름) -> 0(같음) -> 0x00...
                    // 0(같음) -> 1(다름) -> 0xFF...
                    (non_zero_bit ^ 1).wrapping_neg()
                }

                #[inline(always)]
                fn ct_ne(self, other: Self) -> Self {
                    !self.ct_eq(other)
                }

                #[inline(always)]
                fn ct_select(self, other: Self, mask: Self) -> Self {
                    // 컴파일러가 분기문(Branch)이나 조건부 이동(CMOV) 최적화를
                    // 잘못 수행하지 않도록 입력값과 마스크를 Black Box로 처리
                    let a = core::hint::black_box(self);
                    let b = core::hint::black_box(other);
                    let m = core::hint::black_box(mask);

                    // 표준 Constant-Time Select 로직 (XOR Swap 방식)
                    // mask가 11...11이면: b ^ (11...11 & (a ^ b)) = b ^ a ^ b = a
                    // mask가 00...00이면: b ^ (00...00 & (a ^ b)) = b ^ 0 = b
                    b ^ (m & (a ^ b))
                }
            }
        )+
    };
}

// 모든 정수 타입에 대해 구현 적용 (비트 수 자동 계산)
impl_ct_ops!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);
