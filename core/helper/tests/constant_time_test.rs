use entlib_native_helper::constant_time::ConstantTimeOps;

#[test]
fn test_ct_eq_u32() {
    let a: u32 = 0xDEADBEEF;
    let b: u32 = 0xDEADBEEF;
    let c: u32 = 0xCAFEBABE;

    // Equal case
    assert_eq!(a.ct_eq(b), !0); // Expect All 1s
    assert_eq!(a.ct_ne(b), 0); // Expect 0

    // Not Equal case
    assert_eq!(a.ct_eq(c), 0); // Expect 0
    assert_eq!(a.ct_ne(c), !0); // Expect All 1s
}

#[test]
fn test_ct_integrated_flow() {
    let secret = 12345u64;
    let guess_correct = 12345u64;
    let guess_wrong = 67890u64;

    let val_true = 100u64;
    let val_false = 200u64;

    // Scenario 1: Correct Guess
    let mask = secret.ct_eq(guess_correct);
    let result = val_true.ct_select(val_false, mask);
    assert_eq!(result, val_true);

    // Scenario 2: Wrong Guess
    let mask = secret.ct_eq(guess_wrong);
    let result = val_true.ct_select(val_false, mask);
    assert_eq!(result, val_false);
}

#[test]
fn test_ct_is_zero_nonzero() {
    let zero: i32 = 0;
    let non_zero: i32 = 123;
    let neg_val: i32 = -1;

    // Zero check
    assert_eq!(zero.ct_is_zero(), !0);
    assert_eq!(zero.ct_is_nonzero(), 0);

    // Non-zero check
    assert_eq!(non_zero.ct_is_zero(), 0);
    assert_eq!(non_zero.ct_is_nonzero(), !0);

    // Negative value check (also non-zero)
    assert_eq!(neg_val.ct_is_zero(), 0);
    assert_eq!(neg_val.ct_is_nonzero(), !0);
}

#[test]
fn test_ct_is_negative() {
    let pos: i32 = 100;
    let neg: i32 = -100;
    let zero: i32 = 0;

    // Positive number
    assert_eq!(pos.ct_is_negative(), 0);

    // Negative number
    assert_eq!(neg.ct_is_negative(), !0);

    // Zero is not negative
    assert_eq!(zero.ct_is_negative(), 0);

    // Unsigned types (MSB check)
    let u_small: u8 = 0x0F; // 0000 1111
    let u_large: u8 = 0xF0; // 1111 0000 (MSB set)

    assert_eq!(u_small.ct_is_negative(), 0);
    assert_eq!(u_large.ct_is_negative(), !0);
}
