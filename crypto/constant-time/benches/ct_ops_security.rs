/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::time::Duration;

use entlib_native_constant_time::constant_time::ConstantTimeOps;

//
// Macros — 반복 제거를 위한 보안성 벤치마크 매크로
//

/// 단항 CT 연산의 타이밍 일관성 벤치마크.
/// 같은 그룹 내 입력 클래스들의 신뢰구간이 겹쳐야 상수-시간 보장.
macro_rules! security_bench_unary {
    ($c:expr, $group_name:expr, $op:ident,
     $($class:expr => $val:expr),+ $(,)?) => {{
        let mut group = $c.benchmark_group($group_name);
        group.measurement_time(Duration::from_secs(5));
        group.sample_size(1000);
        $(
            group.bench_with_input(
                BenchmarkId::new($class, ""),
                &$val,
                |b, &v| b.iter(|| std::hint::black_box(std::hint::black_box(v).$op())),
            );
        )+
        group.finish();
    }};
}

/// 이항 CT 연산의 타이밍 일관성 벤치마크.
macro_rules! security_bench_binary {
    ($c:expr, $group_name:expr, $op:ident,
     $($class:expr => ($a:expr, $b:expr)),+ $(,)?) => {{
        let mut group = $c.benchmark_group($group_name);
        group.measurement_time(Duration::from_secs(5));
        group.sample_size(1000);
        $(
            group.bench_with_input(
                BenchmarkId::new($class, ""),
                &($a, $b),
                |b, &(a, other)| b.iter(|| {
                    std::hint::black_box(
                        std::hint::black_box(a).$op(std::hint::black_box(other))
                    )
                }),
            );
        )+
        group.finish();
    }};
}

/// 삼항 ct_select 연산의 타이밍 일관성 벤치마크.
macro_rules! security_bench_select {
    ($c:expr, $group_name:expr,
     $($class:expr => ($a:expr, $b:expr, $mask:expr)),+ $(,)?) => {{
        let mut group = $c.benchmark_group($group_name);
        group.measurement_time(Duration::from_secs(5));
        group.sample_size(1000);
        $(
            group.bench_with_input(
                BenchmarkId::new($class, ""),
                &($a, $b, $mask),
                |b, &(a, other, mask)| b.iter(|| {
                    std::hint::black_box(
                        std::hint::black_box(a).ct_select(
                            std::hint::black_box(other),
                            std::hint::black_box(mask),
                        )
                    )
                }),
            );
        )+
        group.finish();
    }};
}

//
// ct_eq — 이항 (equal 판별)
//

fn ct_eq_security(c: &mut Criterion) {
    // u8 (Tier2)
    security_bench_binary!(c, "security/ct_eq/u8", ct_eq,
        "equal_zeros"    => (0u8, 0u8),
        "equal_ones"     => (0xFFu8, 0xFFu8),
        "hamming_1_diff" => (0u8, 1u8),
        "hamming_max"    => (0x55u8, 0xAAu8),
        "random"         => (0x5Cu8, 0xA3u8),
    );
    // u32 (Tier1)
    security_bench_binary!(c, "security/ct_eq/u32", ct_eq,
        "equal_zeros"    => (0u32, 0u32),
        "equal_ones"     => (!0u32, !0u32),
        "hamming_1_diff" => (0u32, 1u32),
        "hamming_max"    => (0x5555_5555u32, 0xAAAA_AAAAu32),
        "random"         => (0x5C3A_7F91u32, 0xA3C5_806Eu32),
    );
    // u64 (Tier1)
    security_bench_binary!(c, "security/ct_eq/u64", ct_eq,
        "equal_zeros"    => (0u64, 0u64),
        "equal_ones"     => (!0u64, !0u64),
        "hamming_1_diff" => (0u64, 1u64),
        "hamming_max"    => (0x5555_5555_5555_5555u64, 0xAAAA_AAAA_AAAA_AAAAu64),
        "random"         => (0x5C3A_7F91_D2B8_4E06u64, 0xA3C5_806E_2D47_B1F9u64),
    );
    // u128 (Tier2)
    security_bench_binary!(c, "security/ct_eq/u128", ct_eq,
        "equal_zeros"    => (0u128, 0u128),
        "equal_ones"     => (!0u128, !0u128),
        "hamming_1_diff" => (0u128, 1u128),
        "hamming_max"    => (0x5555_5555_5555_5555_5555_5555_5555_5555u128,
                            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128),
        "random"         => (0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
                            0xA3C5_806E_2D47_B1F9_E5D4_C3B2_A190_8F76u128),
    );
}

//
// ct_ne — 이항 (not-equal 판별)
//

fn ct_ne_security(c: &mut Criterion) {
    security_bench_binary!(c, "security/ct_ne/u8", ct_ne,
        "equal_zeros"    => (0u8, 0u8),
        "equal_ones"     => (0xFFu8, 0xFFu8),
        "hamming_1_diff" => (0u8, 1u8),
        "hamming_max"    => (0x55u8, 0xAAu8),
        "random"         => (0x5Cu8, 0xA3u8),
    );
    security_bench_binary!(c, "security/ct_ne/u32", ct_ne,
        "equal_zeros"    => (0u32, 0u32),
        "equal_ones"     => (!0u32, !0u32),
        "hamming_1_diff" => (0u32, 1u32),
        "hamming_max"    => (0x5555_5555u32, 0xAAAA_AAAAu32),
        "random"         => (0x5C3A_7F91u32, 0xA3C5_806Eu32),
    );
    security_bench_binary!(c, "security/ct_ne/u64", ct_ne,
        "equal_zeros"    => (0u64, 0u64),
        "equal_ones"     => (!0u64, !0u64),
        "hamming_1_diff" => (0u64, 1u64),
        "hamming_max"    => (0x5555_5555_5555_5555u64, 0xAAAA_AAAA_AAAA_AAAAu64),
        "random"         => (0x5C3A_7F91_D2B8_4E06u64, 0xA3C5_806E_2D47_B1F9u64),
    );
    security_bench_binary!(c, "security/ct_ne/u128", ct_ne,
        "equal_zeros"    => (0u128, 0u128),
        "equal_ones"     => (!0u128, !0u128),
        "hamming_1_diff" => (0u128, 1u128),
        "hamming_max"    => (0x5555_5555_5555_5555_5555_5555_5555_5555u128,
                            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128),
        "random"         => (0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
                            0xA3C5_806E_2D47_B1F9_E5D4_C3B2_A190_8F76u128),
    );
}

//
// ct_is_zero — 단항
//

fn ct_is_zero_security(c: &mut Criterion) {
    security_bench_unary!(c, "security/ct_is_zero/u8", ct_is_zero,
        "all_zeros"   => 0u8,
        "all_ones"    => 0xFFu8,
        "hamming_1"   => 1u8,
        "hamming_max" => 0xAAu8,
        "random"      => 0x5Cu8,
    );
    security_bench_unary!(c, "security/ct_is_zero/u32", ct_is_zero,
        "all_zeros"   => 0u32,
        "all_ones"    => !0u32,
        "hamming_1"   => 1u32,
        "hamming_max" => 0xAAAA_AAAAu32,
        "random"      => 0x5C3A_7F91u32,
    );
    security_bench_unary!(c, "security/ct_is_zero/u64", ct_is_zero,
        "all_zeros"   => 0u64,
        "all_ones"    => !0u64,
        "hamming_1"   => 1u64,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAAu64,
        "random"      => 0x5C3A_7F91_D2B8_4E06u64,
    );
    security_bench_unary!(c, "security/ct_is_zero/u128", ct_is_zero,
        "all_zeros"   => 0u128,
        "all_ones"    => !0u128,
        "hamming_1"   => 1u128,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        "random"      => 0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
    );
}

//
// ct_is_nonzero — 단항
//

fn ct_is_nonzero_security(c: &mut Criterion) {
    security_bench_unary!(c, "security/ct_is_nonzero/u8", ct_is_nonzero,
        "all_zeros"   => 0u8,
        "all_ones"    => 0xFFu8,
        "hamming_1"   => 1u8,
        "hamming_max" => 0xAAu8,
        "random"      => 0x5Cu8,
    );
    security_bench_unary!(c, "security/ct_is_nonzero/u32", ct_is_nonzero,
        "all_zeros"   => 0u32,
        "all_ones"    => !0u32,
        "hamming_1"   => 1u32,
        "hamming_max" => 0xAAAA_AAAAu32,
        "random"      => 0x5C3A_7F91u32,
    );
    security_bench_unary!(c, "security/ct_is_nonzero/u64", ct_is_nonzero,
        "all_zeros"   => 0u64,
        "all_ones"    => !0u64,
        "hamming_1"   => 1u64,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAAu64,
        "random"      => 0x5C3A_7F91_D2B8_4E06u64,
    );
    security_bench_unary!(c, "security/ct_is_nonzero/u128", ct_is_nonzero,
        "all_zeros"   => 0u128,
        "all_ones"    => !0u128,
        "hamming_1"   => 1u128,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        "random"      => 0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
    );
}

//
// ct_is_negative — 단항 (MSB 검사)
//

fn ct_is_negative_security(c: &mut Criterion) {
    security_bench_unary!(c, "security/ct_is_negative/u8", ct_is_negative,
        "all_zeros"   => 0u8,
        "all_ones"    => 0xFFu8,
        "hamming_1"   => 1u8,
        "hamming_max" => 0xAAu8,
        "random"      => 0x5Cu8,
    );
    security_bench_unary!(c, "security/ct_is_negative/u32", ct_is_negative,
        "all_zeros"   => 0u32,
        "all_ones"    => !0u32,
        "hamming_1"   => 1u32,
        "hamming_max" => 0xAAAA_AAAAu32,
        "random"      => 0x5C3A_7F91u32,
    );
    security_bench_unary!(c, "security/ct_is_negative/u64", ct_is_negative,
        "all_zeros"   => 0u64,
        "all_ones"    => !0u64,
        "hamming_1"   => 1u64,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAAu64,
        "random"      => 0x5C3A_7F91_D2B8_4E06u64,
    );
    security_bench_unary!(c, "security/ct_is_negative/u128", ct_is_negative,
        "all_zeros"   => 0u128,
        "all_ones"    => !0u128,
        "hamming_1"   => 1u128,
        "hamming_max" => 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        "random"      => 0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
    );
}

//
// ct_select — 삼항 (mask 기반 조건 선택)
//

fn ct_select_security(c: &mut Criterion) {
    // u8 (Tier2)
    security_bench_select!(c, "security/ct_select/u8",
        "mask_true_zeros"  => (0u8, 0u8, !0u8),
        "mask_false_zeros" => (0u8, 0u8, 0u8),
        "mask_true_ones"   => (0xFFu8, 0x00u8, !0u8),
        "mask_false_ones"  => (0x00u8, 0xFFu8, 0u8),
        "random_true"      => (0x5Cu8, 0xA3u8, !0u8),
    );
    // u32 (Tier1)
    security_bench_select!(c, "security/ct_select/u32",
        "mask_true_zeros"  => (0u32, 0u32, !0u32),
        "mask_false_zeros" => (0u32, 0u32, 0u32),
        "mask_true_ones"   => (!0u32, 0u32, !0u32),
        "mask_false_ones"  => (0u32, !0u32, 0u32),
        "random_true"      => (0x5C3A_7F91u32, 0xA3C5_806Eu32, !0u32),
    );
    // u64 (Tier1)
    security_bench_select!(c, "security/ct_select/u64",
        "mask_true_zeros"  => (0u64, 0u64, !0u64),
        "mask_false_zeros" => (0u64, 0u64, 0u64),
        "mask_true_ones"   => (!0u64, 0u64, !0u64),
        "mask_false_ones"  => (0u64, !0u64, 0u64),
        "random_true"      => (0x5C3A_7F91_D2B8_4E06u64, 0xA3C5_806E_2D47_B1F9u64, !0u64),
    );
    // u128 (Tier2)
    security_bench_select!(c, "security/ct_select/u128",
        "mask_true_zeros"  => (0u128, 0u128, !0u128),
        "mask_false_zeros" => (0u128, 0u128, 0u128),
        "mask_true_ones"   => (!0u128, 0u128, !0u128),
        "mask_false_ones"  => (0u128, !0u128, 0u128),
        "random_true"      => (0x5C3A_7F91_D2B8_4E06_1A2B_3C4D_5E6F_7089u128,
                              0xA3C5_806E_2D47_B1F9_E5D4_C3B2_A190_8F76u128, !0u128),
    );
}

//
// Criterion 설정
//

criterion_group!(
    benches,
    ct_eq_security,
    ct_ne_security,
    ct_is_zero_security,
    ct_is_nonzero_security,
    ct_is_negative_security,
    ct_select_security,
);
criterion_main!(benches);
