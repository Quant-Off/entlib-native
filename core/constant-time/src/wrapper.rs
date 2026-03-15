use crate::choice::Choice;
use crate::traits::*;

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_eq(a: &u64, b: &u64) -> Choice {
    a.ct_eq(b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_is_ge(a: &u64, b: &u64) -> Choice {
    a.ct_is_ge(b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_is_negative(a: &u64) -> Choice {
    a.ct_is_negative()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_ne(a: &u64, b: &u64) -> Choice {
    a.ct_ne(b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_is_zero(a: &u64) -> Choice {
    a.ct_is_zero()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_select(a: &u64, b: &u64, choice: Choice) -> u64 {
    u64::ct_select(a, b, choice)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_u64_ct_swap(a: &mut u64, b: &mut u64, choice: Choice) {
    u64::ct_swap(a, b, choice)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_choice_from_mask_normalized(a: u8) -> Choice {
    Choice::from_mask_normalized(a)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_choice_not(choice: Choice) -> Choice {
    choice.choice_not()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_verify_choice_unwrap_u8(choice: Choice) -> u8 {
    choice.unwrap_u8()
}
