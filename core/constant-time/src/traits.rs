use crate::choice::Choice;

/// 두 데이터의 동일성 여부를 상수-시간으로 판별합니다.
pub trait ConstantTimeEq {
    /// 두 값이 동일하면 Choice(0xFF)를, 다르면 Choice(0x00)을 반환합니다.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// 두 값이 다르면 Choice(0xFF)를 반환합니다.
    /// 기본적으로 ct_eq의 결과를 반전(NOT)시켜 제공합니다.
    #[inline(always)]
    fn ct_ne(&self, other: &Self) -> Choice {
        self.ct_eq(other).choice_not()
    }

    fn ct_is_ge(&self, other: &Self) -> Choice;
}

/// 조건에 따라 두 값 중 하나를 상수-시간으로 선택합니다.
pub trait ConstantTimeSelect: Sized {
    /// choice가 True(0xFF)이면 `a`를, False(0x00)이면 `b`를 반환합니다.
    /// 어떠한 분기문(if/else, match)도 사용되어서는 안 됩니다.
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self;
}

/// 조건에 따라 두 변수의 값을 상수-시간으로 교환(Swap)합니다.
/// Montgomery Ladder와 같은 암호화 알고리즘에 필수적입니다.
pub trait ConstantTimeSwap: Sized {
    /// choice가 True(0xFF)이면 `a`와 `b`의 값을 교환하고, False(0x00)이면 그대로 둡니다.
    fn ct_swap(a: &mut Self, b: &mut Self, choice: Choice);
}

/// 값이 0인지 상수-시간으로 판별합니다. (BigInt 및 메모리 소거 검증용)
pub trait ConstantTimeIsZero {
    /// 값이 0이면 Choice(0xFF)를, 0이 아니면 Choice(0x00)을 반환합니다.
    fn ct_is_zero(&self) -> Choice;
}

/// 값의 최상위 비트(MSB)가 1인지 상수-시간으로 판별합니다.
///
/// 암호학적 다중 정밀도 연산에서 `wrapping_sub`의 언더플로우(Borrow)를
/// 분기 없이 감지하는 데 활용됩니다.
///
/// # 사용 사례
/// `a.wrapping_sub(b)` 수행 후 결과의 MSB가 1이면 `a < b`임을 상수-시간으로 판별합니다.
/// 이 특성은 상수-시간 모듈로 보정, 조건부 스왑, 상수-시간 Base64 범위 검사 등에
/// 광범위하게 사용됩니다.
///
/// # 보안 보장
/// - MSB 추출은 단일 우측 시프트(SHR) 명령어로 수행되며 분기가 없습니다.
/// - `wrapping_neg`를 이용한 마스크 생성은 CPU 분기 예측기를 자극하지 않습니다.
pub trait ConstantTimeIsNegative {
    /// MSB가 1이면 `Choice(0xFF)`, 0이면 `Choice(0x00)`을 반환합니다.
    fn ct_is_negative(&self) -> Choice;
}
