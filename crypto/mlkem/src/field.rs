pub(crate) const Q: i32 = 3329;

// # Safety
// All inputs must be in [0, Q-1]. Outputs are in [0, Q-1].

/// Constant-time addition mod Q.
#[inline(always)]
pub(crate) fn add_q(a: i32, b: i32) -> i32 {
    let sum = a + b;
    let d = sum - Q;
    let mask = d >> 31;
    (d & !mask) | (sum & mask)
}

/// Constant-time subtraction mod Q.
#[inline(always)]
pub(crate) fn sub_q(a: i32, b: i32) -> i32 {
    let d = a - b;
    let mask = d >> 31;
    (d & !mask) | ((d + Q) & mask)
}

/// Multiplication mod Q via i64 intermediate.
#[inline(always)]
pub(crate) fn mul_q(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64).rem_euclid(Q as i64)) as i32
}

/// Reduce an arbitrary i32 into [0, Q-1].
#[inline(always)]
pub(crate) fn reduce_q(x: i32) -> i32 {
    x.rem_euclid(Q)
}
