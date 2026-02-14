use entlib_native_helper::constant_time_asm::CtPrimitive;

macro_rules! test_ct_primitive {
    ($test_name:ident, $t:ty, $zero:expr, $one:expr, $neg:expr) => {
        #[test]
        fn $test_name() {
            let zero: $t = $zero;
            let one: $t = $one;
            let neg: $t = $neg;
            let max: $t = !0;

            // ct_nonzero
            assert_eq!(zero.ct_nonzero(), 0);
            assert_eq!(one.ct_nonzero(), max);
            assert_eq!(neg.ct_nonzero(), max);

            // ct_zero
            assert_eq!(zero.ct_zero(), max);
            assert_eq!(one.ct_zero(), 0);

            // ct_negative
            // Unsigned types: check MSB
            // Signed types: check sign bit
            assert_eq!(zero.ct_negative(), 0);
            assert_eq!(one.ct_negative(), 0);
            assert_eq!(neg.ct_negative(), max);

            // ct_equal
            assert_eq!(zero.ct_equal(zero), max);
            assert_eq!(zero.ct_equal(one), 0);
            assert_eq!(one.ct_equal(one), max);

            // ct_not_equal
            assert_eq!(zero.ct_not_equal(zero), 0);
            assert_eq!(zero.ct_not_equal(one), max);

            // ct_mux
            // mask = max (all 1s) -> select first arg
            assert_eq!(one.ct_mux(zero, max), one);
            // mask = 0 -> select second arg
            assert_eq!(one.ct_mux(zero, 0), zero);
        }
    };
}

// Unsigned types
test_ct_primitive!(test_u8, u8, 0, 1, 0x80);
test_ct_primitive!(test_u16, u16, 0, 1, 0x8000);
test_ct_primitive!(test_u32, u32, 0, 1, 0x80000000);
test_ct_primitive!(test_u64, u64, 0, 1, 0x8000000000000000);
test_ct_primitive!(test_u128, u128, 0, 1, 0x80000000000000000000000000000000);
test_ct_primitive!(test_usize, usize, 0, 1, 1 << (usize::BITS - 1));

// Signed types
test_ct_primitive!(test_i8, i8, 0, 1, -1);
test_ct_primitive!(test_i16, i16, 0, 1, -1);
test_ct_primitive!(test_i32, i32, 0, 1, -1);
test_ct_primitive!(test_i64, i64, 0, 1, -1);
test_ct_primitive!(test_i128, i128, 0, 1, -1);
test_ct_primitive!(test_isize, isize, 0, 1, -1);

#[test]
fn test_ct_fence_optimization_barrier() {
    // This test mainly checks if it compiles and runs without crashing.
    // Verifying actual optimization barrier behavior is hard in unit tests.
    let val = 42u32;
    let fenced = val.ct_fence();
    assert_eq!(val, fenced);
}
