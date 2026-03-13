#![no_std]

pub mod choice;
pub mod traits;

use choice::Choice;
use traits::{
    ConstantTimeEq, ConstantTimeIsNegative, ConstantTimeIsZero, ConstantTimeSelect,
    ConstantTimeSwap,
};

/// 기본 부호 없는 정수형(Unsigned Integers)에 대한 상수-시간 연산을
/// 일괄 구현하는 매크로입니다.
macro_rules! impl_constant_time_for_uint {
    ($t:ty) => {
        impl ConstantTimeEq for $t {
            #[inline(always)]
            fn ct_eq(&self, other: &Self) -> Choice {
                // XOR 연산
                // 두 값이 같으면 v는 0, 다르면 0이 아닌 값이 됨
                let v = *self ^ *other;

                // OR와 2의 보수(wrapping_neg) 활용
                // v가 0이면 v | v.wrapping_neg() 도 0임
                // v가 0이 아니면, v | v.wrapping_neg() 의 최상위 비트(MSB)는 항상 1이 됨
                // 이를 통해 MSB를 LSB 위치로 이동시킴
                let msb = (v | v.wrapping_neg()) >> (<$t>::BITS - 1);

                // 마스크 생성
                // v가 0(같음)이면 msb는 0. msb ^ 1 은 1. 1의 2의 보수는 0xFF (True)
                // v가 0이 아님(다름)이면 msb는 1. msb ^ 1 은 0. 0의 2의 보수는 0x00 (False)
                let mask = ((msb as u8) ^ 1).wrapping_neg();

                Choice::from_mask_normalized(mask)
            }

            #[inline(always)]
            fn ct_is_ge(&self, other: &Self) -> Choice {
                // 부호 없는 정수의 대소 비교(self >= other)를 상수-시간으로 판별하기 위해
                // 뺄셈 연산의 언더플로우(Borrow) 발생 여부를 비트 논리로 계산
                // Borrow 방정식: (~A & B) | (~(A ^ B) & (A - B))
                // 결과의 최상위 비트(MSB)가 1이면 self < other (언더플로우 발생), 0이면 self >= other
                let sub = self.wrapping_sub(*other);
                let borrow = (!*self & *other) | (!(*self ^ *other) & sub);

                // 최상위 비트(MSB) 추출
                // 이전 <u32>::BITS 하드코딩으로 인한 치명적 결함을 동적 타입 크기(<$t>::BITS)로 해결
                let borrow_msb = (borrow >> (<$t>::BITS - 1)) as u8;

                // 마스크 생성
                // borrow_msb가 0 (self >= other) -> 0 ^ 1 = 1 -> wrapping_neg(1) = 0xFF (True)
                // borrow_msb가 1 (self < other)  -> 1 ^ 1 = 0 -> wrapping_neg(0) = 0x00 (False)
                let mask = (borrow_msb ^ 1).wrapping_neg();

                Choice::from_mask_normalized(mask)
            }
        }

        impl ConstantTimeSelect for $t {
            #[inline(always)]
            fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
                // 부호 확장(Sign-Extension) 트릭
                // 0x00 as i8 -> 0 -> $t로 캐스팅하면 모든 비트가 0 (0x0000...)
                // 0xFF as i8 -> -1 -> $t로 캐스팅하면 모든 비트가 1 (0xFFFF...)
                let mask = (choice.unwrap_u8() as i8) as $t;

                // 마스크에 따라 a 또는 b를 비트 단위로 선택 (분기 없음)
                (a & mask) | (b & !mask)
            }
        }

        impl ConstantTimeSwap for $t {
            #[inline(always)]
            fn ct_swap(a: &mut Self, b: &mut Self, choice: Choice) {
                let mask = (choice.unwrap_u8() as i8) as $t;
                // XOR 스왑 알고리즘을 마스크와 결합
                // mask가 모든 비트가 1이면 t = a ^ b, mask가 0이면 t = 0
                let t = (*a ^ *b) & mask;

                // t가 0이면 원래 값을 유지, t가 a ^ b이면 값이 교환됨
                *a ^= t;
                *b ^= t;
            }
        }

        impl ConstantTimeIsZero for $t {
            #[inline(always)]
            fn ct_is_zero(&self) -> Choice {
                // 값과 0을 상수-시간으로 비교
                self.ct_eq(&0)
            }
        }

        impl ConstantTimeIsNegative for $t {
            #[inline(always)]
            fn ct_is_negative(&self) -> Choice {
                // MSB(최상위 비트)를 LSB 위치로 이동시켜 0 또는 1을 추출
                // 예: u8에서 *self >> 7, u64에서 *self >> 63
                let msb = (*self >> (<$t>::BITS - 1)) as u8 & 1;

                // 1u8.wrapping_neg() = 0xFF (True), 0u8.wrapping_neg() = 0x00 (False)
                // 단일 NEG 명령어로 컴파일되어 분기가 없음
                Choice::from_mask_normalized(msb.wrapping_neg())
            }
        }
    };
}

impl_constant_time_for_uint!(u8);
impl_constant_time_for_uint!(u16);
impl_constant_time_for_uint!(u32);
impl_constant_time_for_uint!(u64);
impl_constant_time_for_uint!(u128);
impl_constant_time_for_uint!(usize);

/// 기본 부호 있는 정수형(Signed Integers)에 대한 상수-시간 연산을
/// 분기 없이 안전하게 일괄 구현하는 매크로입니다.
macro_rules! impl_constant_time_for_sint {
    ($s_type:ty, $u_type:ty) => {
        impl ConstantTimeEq for $s_type {
            #[inline(always)]
            fn ct_eq(&self, other: &Self) -> Choice {
                // 동일성 비교는 비트 패턴의 일치 여부만 확인하기 때문에
                // 부호 없는 정수로 강제 캐스팅하여 기존 산술 시프트 취약점 회피
                let a = *self as $u_type;
                let b = *other as $u_type;

                // 기 검증된 Unsigned의 상수-시간 동일성 비교 로직으로 위임
                a.ct_eq(&b)
            }

            #[inline(always)]
            fn ct_is_ge(&self, other: &Self) -> Choice {
                // 부호 있는 정수의 대소 비교 시 타이밍 공격 방지
                // 2의 보수 체계에서 부호 비트(MSB)를 반전(XOR)시키면
                // 값의 수학적 대소 순서를 보존한 채 부호 없는 정수 도메인으로 안전하게 매핑됨
                let sign_mask = (1 as $u_type) << (<$s_type>::BITS - 1);
                let a_mapped = (*self as $u_type) ^ sign_mask;
                let b_mapped = (*other as $u_type) ^ sign_mask;

                // 변환된 값을 바탕으로 안전성이 입증된 부호 없는 정수의 대소 비교 수행
                a_mapped.ct_is_ge(&b_mapped)
            }
        }

        impl ConstantTimeIsNegative for $s_type {
            #[inline(always)]
            fn ct_is_negative(&self) -> Choice {
                // 산술 시프트로 인한 마스크 오염(예: 0x02) 방지를 위해
                // 부호 없는 정수로 변환 후 논리 시프트 강제
                let u_val = *self as $u_type;
                let msb = (u_val >> (<$s_type>::BITS - 1)) as u8 & 1;

                // 단일 NEG 명령어로 분기 없이 마스크 생성 (0x00 또는 0xFF 보장)
                Choice::from_mask_normalized(msb.wrapping_neg())
            }
        }

        impl ConstantTimeSelect for $s_type {
            #[inline(always)]
            fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
                // Sign-Extension 트릭은 부호 있는 정수에서도 비트 마스킹에 유효
                let mask = (choice.unwrap_u8() as i8) as $s_type;
                (a & mask) | (b & !mask)
            }
        }

        impl ConstantTimeSwap for $s_type {
            #[inline(always)]
            fn ct_swap(a: &mut Self, b: &mut Self, choice: Choice) {
                let mask = (choice.unwrap_u8() as i8) as $s_type;
                let t = (*a ^ *b) & mask;
                *a ^= t;
                *b ^= t;
            }
        }

        impl ConstantTimeIsZero for $s_type {
            #[inline(always)]
            fn ct_is_zero(&self) -> Choice {
                self.ct_eq(&0)
            }
        }
    };
}

impl_constant_time_for_sint!(i8, u8);
impl_constant_time_for_sint!(i16, u16);
impl_constant_time_for_sint!(i32, u32);
impl_constant_time_for_sint!(i64, u64);
impl_constant_time_for_sint!(i128, u128);
impl_constant_time_for_sint!(isize, usize);