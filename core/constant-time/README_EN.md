# Constant-Time Crate (entlib-native-constant-time)

> Q. T. Felix (Modified: 25.03.19 UTC+9)
> 
> [Korean README](README.md)

`entlib-native-constant-time` is a `no_std` compatible crate designed to fundamentally block timing side-channel attacks that occur in cryptographic implementations. This crate provides constant-time primitives that eliminate all conditional branches that depend on secret data and ensure that the operation time is completely independent of the secrecy of the input value.

## Security Threat Model

Modern high-performance processors utilize various microarchitectural optimization techniques such as branch predictors, speculative execution, and data-dependent pipeline delays. If there is an `if`/`else` branch or a conditional return (early return) with a secret value as an operand, an attacker can statistically recover the secret value just by precise time measurement. This crate aims to completely eliminate this attack surface.

## Core Abstraction: Choice Struct

The `Choice` struct is an opaque type that safely represents the result of a cryptographic conditional operation. It is designed to have only one of two states internally, `0x00` (false) or `0xFF` (true), and as long as this invariant is maintained, bitwise operations (`&`, `|`, `^`, `!`) are mathematically equivalent to logical operations and do not cause branching.

```rust
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Choice(u8); // Only 0x00 or 0xFF is allowed
```

By keeping the internal fields private, it prevents arbitrary byte values from being directly injected into `Choice`. From the outside, `Choice` can only be created through the `from_mask_normalized` function, which normalizes an arbitrary `u8` input to `0x00` or `0xFF`.

> [!NOTE]
> **Normalization Mechanism**: For an arbitrary mask value $m \in [0, 255]$, the normalization process proceeds as follows.
> 
> First, if we calculate $m' = m \mathbin{|} (-m)$, then when $m = 0$, $m' = 0$, and when $m \ne 0$, the most significant bit (MSB) of $m'$ must be 1.
> 
> After that, if we extract the MSB with $b = m' \gg 7$, then $b \in \{0, 1\}$ is confirmed, and the final mask $c = -b$ (2's complement) yields `0x00` if $b = 0$ and `0xFF` if $b = 1$.
> 
> This series of processes is compiled into only three non-branching CPU instructions.

The `unwrap_u8` method returns via `core::hint::black_box` to prevent the compiler from causing branching by constant folding the internal value.

## Trait Specification

### `ConstantTimeEq`

Determines the equality of two values in constant time. The `ct_eq` function returns `Choice(0xFF)` (equal), `ct_ne` returns `Choice(0xFF)` (not equal), and `ct_is_ge` determines the greater-than-or-equal-to relationship.

> [!NOTE]
> **Equality Determination (`ct_eq`)**: For two unsigned integers $a, b$, we calculate $v = a \oplus b$.
>
> If $a = b$, then $v = 0$ and $v \mathbin{|} (-v) = 0$, so the MSB is 0.
> 
> If $a \ne b$, then $v \ne 0$ and the MSB of $v \mathbin{|} (-v)$ must be 1.
> 
> After extracting the MSB, we calculate the final mask with $\mathtt{mask} = -((\text{msb} \oplus 1))$.
> 
> `0xFF` is returned if $a = b$, and `0x00` is returned if $a \ne b$.

```rust
let v = *self ^ *other;
let msb = (v | v.wrapping_neg()) >> (u64::BITS - 1);
let mask = ((msb as u8) ^ 1).wrapping_neg(); // 0x00 or 0xFF
```

> [!NOTE]
> **Greater-Than-or-Equal-To Determination (`ct_is_ge`)**: The determination of $a \ge b$ for unsigned integers is reduced to whether an underflow (borrow) occurs in the subtraction $a - b$.
> 
> In the borrow equation $\text{borrow} = (\lnot a \land b) \mathbin{|} (\lnot(a \oplus b) \land (a - b))$, if the MSB of the result is 1, then $a < b$, and if it is 0, then $a \ge b$.
> 
> This formula dynamically refers to the type size `<$t>::BITS` to operate correctly regardless of the integer width.

When determining the equality of signed integers, to avoid MSB contamination due to arithmetic shifts, they are reinterpreted as unsigned integers (bitwise reinterpretation) and then delegated to the existing logic. When comparing magnitudes, the sign bit is inverted with XOR in the 2's complement representation ($a' = a_u \oplus 2^{N-1}$) to safely map to the unsigned integer domain while preserving the mathematical order.

### `ConstantTimeSelect`

`ct_select(a, b, choice)` returns `a` if `choice` is `0xFF`, and `b` if `choice` is `0x00`. It utilizes the sign-extension trick to reinterpret the `u8` inside `choice` as `i8` and then sign-extend it to the target type. `0xFF as i8` is $-1$, and extending it to an arbitrary integer type results in a mask with all bits set to 1. This allows for bitwise multiplexing without branching.

$$\text{result} = (a \land \text{mask}) \mathbin{|} (b \land \lnot\text{mask})$$

```rust
let mask = (choice.unwrap_u8() as i8) as T;
(a & mask) | (b & !mask)
```

### `ConstantTimeSwap`

`ct_swap(a, b, choice)` swaps the values of `a` and `b` if `choice` is `0xFF`, and keeps the original values if `choice` is `0x00`. It combines the XOR swap algorithm with a conditional mask to implement a branchless swap without an additional temporary buffer.

$$t = (a \oplus b) \land \text{mask}, \quad a' = a \oplus t, \quad b' = b \oplus t$$

This technique is essential in cryptographic algorithms where conditional swaps by secret bits are frequently required, such as the Montgomery Ladder in Elliptic Curve Scalar Multiplication (ECSM).

### `ConstantTimeIsZero` and `ConstantTimeIsNegative`

`ct_is_zero` determines if a value is zero and delegates to the existing `ct_eq` implementation to eliminate duplicate logic. `ct_is_negative` determines by extracting the MSB with a logical shift. For signed integers, to prevent mask contamination due to arithmetic shifts, they must be converted to unsigned integers before performing the shift.

$$\text{mask} = -\left(\left(\text{val}_u \gg (N-1)\right) \land 1\right)$$

This operation is compiled into only a single `SHR` instruction and a single `NEG` instruction. `ct_is_negative` is used to detect underflow of `wrapping_sub` without branching in multi-precision arithmetic or to determine the need for modular reduction.

## Scope of Application

All traits in this crate are implemented for the standard Rust integer types `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, `i8`, `i16`, `i32`, `i64`, `i128`, `isize` through declarative macros. Each implementation has the `#[inline(always)]` annotation, so there is no call overhead.

## Audit Infrastructure

### `audit_mode` Feature: Assembly Inspection Support

Activating the `audit_mode` feature compiles the `wrapper` module. This module exposes audit-only functions with the `#[inline(never)]` and `#[unsafe(no_mangle)]` annotations, forcing the compiler not to inline the functions or mangle the symbols. This allows for direct inspection of the assembly generated by `objdump` or `llvm-objdump` to check for the insertion of unintended branch instructions (`jne`, `je`, `cmov`, etc.).

```bash
cargo build --release -p entlib-native-constant-time --features audit_mode
objdump -d target/release/libentlib_native_constant_time.rlib | grep -E 'j[a-z]+'
```

### `valgrind_taint_audit` Feature: Memcheck-based Taint Tracking

The `valgrind_taint_audit` feature enables taint tracking tests that integrate with Valgrind's Memcheck tool. The test marks secret data as tainted using the Valgrind Client Request interface (`VALGRIND_MAKE_MEM_UNDEFINED`) and checks if the result memory propagates the tainted state after the operation is complete. Valgrind's abstract interpretation reports an error if it detects a branch (`jcc` instruction) that depends on a tainted value. This test is only valid in a Linux `x86_64` environment, and in environments where Valgrind does not exist, the request is ignored and the test passes normally.

```bash
cargo test -p entlib-native-constant-time \
    --features valgrind_taint_audit \
    --target x86_64-unknown-linux-gnu -- --test-threads=1
# valgrind --tool=memcheck --track-origins=yes <binary>
```

> [!WARNING]
> This test may not perform correctly at this time. We are in the process of determining whether this test is strict and correct. If you have an opinion on this test, [please provide active feedback.](../../CONTRIBUTION_EN.md)

### DudeCT Statistical Timing Verification

The `dudect_audit` benchmark verifies statistical timing equivalence based on the DudeCT methodology. It applies Welch's t-test to compare the execution time distributions of more than 100,000 runs for the case where the secret value is the same (`Class::Right`) and the case where it is different (`Class::Left`). If the $|t| < 5$ criterion is met, it is judged that the timing difference between the two groups is not statistically significant.

> [!IMPORTANT]
> This benchmark's t-value can be contaminated in a virtualized environment (VM, public cloud) due to hypervisor intervention and CPU clock fluctuations. To obtain reliable results, it is recommended to run it in a bare-metal environment with power management features (Turbo Boost, C-states) disabled at the BIOS/UEFI level and the CPU frequency fixed.

```bash
cargo +nightly build --release -p entlib-native-constant-time --bench dudect_audit
./target/release/deps/dudect_audit-<hash>
```

## Summary of Design Principles

This crate adopts a defense-in-depth strategy that sequentially applies a three-level security verification system.

1. At the implementation level, it fundamentally blocks the possibility of branching by using only single-instruction bitwise operations such as XOR/OR/NEG.
2. Through assembly auditing (`audit_mode`), it verifies at the assembly level that compiler optimizations have not inserted unexpected branches.
3. Through DudeCT statistical verification and Valgrind taint tracking, it confirms that the final binary maintains timing independence in a real environment.