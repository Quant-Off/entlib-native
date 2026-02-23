#[cfg(test)]
mod tests {
    use entlib_native_constant_time::constant_time::ConstantTimeOps;
    use proptest::prelude::*;
    use subtle::Choice;

    /// subtle 라이브러리의 구현 한계를 우회하기 위한 헬퍼 트레이트
    trait SubtleFallback {
        fn subtle_eq(&self, other: &Self) -> Choice;
        fn subtle_select(a: &Self, b: &Self, choice: Choice) -> Self;
    }

    /// subtle이 공식 지원하는 고정 폭 정수용 위임 매크로
    macro_rules! impl_subtle_native {
        ($($t:ty),*) => {
            $(
                impl SubtleFallback for $t {
                    #[inline(always)]
                    fn subtle_eq(&self, other: &Self) -> Choice {
                        subtle::ConstantTimeEq::ct_eq(self, other)
                    }
                    #[inline(always)]
                    fn subtle_select(a: &Self, b: &Self, choice: Choice) -> Self {
                        <$t as subtle::ConditionallySelectable>::conditional_select(a, b, choice)
                    }
                }
            )*
        }
    }
    impl_subtle_native!(u8, u16, u32, u64);

    /// subtle이 지원하지 않는 타입(usize, u128)을 위한 시맨틱 폴백 매크로
    /// (테스트 환경은 상수 시간 제약이 필요 없으므로 일반 분기문을 사용해 결과값만 대조)
    macro_rules! impl_subtle_manual {
        ($($t:ty),*) => {
            $(
                impl SubtleFallback for $t {
                    #[inline(always)]
                    fn subtle_eq(&self, other: &Self) -> Choice {
                        Choice::from(if self == other { 1 } else { 0 })
                    }
                    #[inline(always)]
                    fn subtle_select(a: &Self, b: &Self, choice: Choice) -> Self {
                        if choice.unwrap_u8() == 1 { *b } else { *a }
                    }
                }
            )*
        }
    }
    impl_subtle_manual!(usize, u128);

    /// 모든 타입에 대해 proptest를 생성하는 매크로
    macro_rules! test_ct_ops_cross_validation {
        ($type:ty, $mod_name:ident) => {
            mod $mod_name {
                use super::*;

                proptest! {
                    #![proptest_config(ProptestConfig::with_cases(10_000))]

                    #[test]
                    fn verify_ct_eq(a in any::<$type>(), b in any::<$type>()) {
                        let subtle_choice = <$type as SubtleFallback>::subtle_eq(&a, &b);
                        let expected_mask: $type = if subtle_choice.unwrap_u8() == 1 { !0 } else { 0 };

                        let actual_mask = a.ct_eq(b);
                        prop_assert_eq!(actual_mask, expected_mask, "ct_eq 불일치: a={}, b={}", a, b);
                    }

                    #[test]
                    fn verify_ct_ne(a in any::<$type>(), b in any::<$type>()) {
                        let subtle_choice = <$type as SubtleFallback>::subtle_eq(&a, &b);
                        let expected_mask: $type = if subtle_choice.unwrap_u8() == 1 { 0 } else { !0 };

                        let actual_mask = a.ct_ne(b);
                        prop_assert_eq!(actual_mask, expected_mask, "ct_ne 불일치: a={}, b={}", a, b);
                    }

                    #[test]
                    fn verify_ct_is_zero(a in any::<$type>()) {
                        let zero: $type = 0;
                        let subtle_choice = <$type as SubtleFallback>::subtle_eq(&a, &zero);
                        let expected_mask: $type = if subtle_choice.unwrap_u8() == 1 { !0 } else { 0 };

                        let actual_mask = a.ct_is_zero();
                        prop_assert_eq!(actual_mask, expected_mask, "ct_is_zero 불일치: a={}", a);
                    }

                    #[test]
                    fn verify_ct_is_nonzero(a in any::<$type>()) {
                        let zero: $type = 0;
                        let subtle_choice = <$type as SubtleFallback>::subtle_eq(&a, &zero);
                        let expected_mask: $type = if subtle_choice.unwrap_u8() == 1 { 0 } else { !0 };

                        let actual_mask = a.ct_is_nonzero();
                        prop_assert_eq!(actual_mask, expected_mask, "ct_is_nonzero 불일치: a={}", a);
                    }

                    #[test]
                    fn verify_ct_select(a in any::<$type>(), b in any::<$type>(), select_a in any::<bool>()) {
                        let choice = subtle::Choice::from(if select_a { 1 } else { 0 });
                        let expected_val = <$type as SubtleFallback>::subtle_select(&a, &b, choice);

                        let mask: $type = if select_a { 0 } else { !0 };
                        let actual_val = a.ct_select(b, mask);

                        prop_assert_eq!(actual_val, expected_val, "ct_select 불일치: a={}, b={}, select_a={}", a, b, select_a);
                    }

                    #[test]
                    fn verify_ct_is_negative(a in any::<$type>()) {
                        let bits = core::mem::size_of::<$type>() as u32 * 8;
                        let is_neg = (a >> (bits - 1)) & 1;
                        let expected_mask: $type = if is_neg == 1 { !0 } else { 0 };

                        let actual_mask = a.ct_is_negative();
                        prop_assert_eq!(actual_mask, expected_mask, "ct_is_negative 불일치: a={}", a);
                    }
                }
            }
        };
    }

    test_ct_ops_cross_validation!(u32, verify_u32);
    test_ct_ops_cross_validation!(u64, verify_u64);
    test_ct_ops_cross_validation!(usize, verify_usize);

    test_ct_ops_cross_validation!(u8, verify_u8);
    test_ct_ops_cross_validation!(u16, verify_u16);
    test_ct_ops_cross_validation!(u128, verify_u128);
}
