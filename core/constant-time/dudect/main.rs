#![allow(unsafe_code)]

//! # DudeCT 통계적 타이밍 분석
//! "dude, is my code constant time?" (Reparaz et al., CHES 2017)
//! 대상: Ubuntu 24.04 x86_64 베어메탈

use std::hint::black_box;

use entlib_native_constant_time::traits::{
    ConstantTimeEq, ConstantTimeIsNegative, ConstantTimeIsZero, ConstantTimeSelect,
    ConstantTimeSwap,
};

const N: usize = 1_000_000;
const CROP: f64 = 0.05;
const T_WARN: f64 = 4.5;
const T_FAIL: f64 = 10.0;
const MAX_CYCLES: u64 = 10_000;

// Xoshiro256** PRNG — 외부 의존성 없음
struct Prng([u64; 4]);

impl Prng {
    fn from_seed(seed: u64) -> Self {
        let mut x = seed;
        let mut sm = || {
            x = x.wrapping_add(0x9e3779b97f4a7c15);
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
            x ^ (x >> 31)
        };
        Self([sm(), sm(), sm(), sm()])
    }

    #[inline]
    fn u64(&mut self) -> u64 {
        let r = self.0[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.0[1] << 17;
        self.0[2] ^= self.0[0];
        self.0[3] ^= self.0[1];
        self.0[1] ^= self.0[2];
        self.0[0] ^= self.0[3];
        self.0[2] ^= t;
        self.0[3] = self.0[3].rotate_left(45);
        r
    }
}

/// # Security Note
/// LFENCE는 이전 명령어가 완전히 retire된 후 RDTSC가 실행되도록 보장하여
/// 측정 외부 명령어가 측정 구간으로 재정렬되는 것을 방지합니다.
#[inline(always)]
fn tsc() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
    }
}

// Welch's t-검정 — Welford 온라인 알고리즘 (수치 안정성)
#[derive(Default)]
struct Ttest {
    n:    [u64; 2],
    mean: [f64; 2],
    m2:   [f64; 2],
}

impl Ttest {
    fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1;
        let d = x - self.mean[class];
        self.mean[class] += d / self.n[class] as f64;
        self.m2[class] += d * (x - self.mean[class]);
    }

    fn t(&self) -> f64 {
        let (n0, n1) = (self.n[0] as f64, self.n[1] as f64);
        if n0 < 2.0 || n1 < 2.0 {
            return 0.0;
        }
        let se = ((self.m2[0] / (n0 - 1.0)) / n0 + (self.m2[1] / (n1 - 1.0)) / n1).sqrt();
        if se == 0.0 { 0.0 } else { (self.mean[0] - self.mean[1]) / se }
    }
}

fn parse_args() -> usize {
    let args: Vec<String> = std::env::args().collect();
    let mut warmup: usize = 10_000;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--warmup" | "-w" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(v) => warmup = v,
                    None => {
                        eprintln!("오류: --warmup 인자는 양의 정수여야 합니다.");
                        eprintln!("사용법: dudect-eval [--warmup <N> | -w <N>]");
                        std::process::exit(1);
                    }
                }
            }
            arg => {
                eprintln!("오류: 알 수 없는 인자 '{arg}'");
                eprintln!("사용법: dudect-eval [--warmup <N> | -w <N>]");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    warmup
}

fn dudect<F>(label: &str, warmup: usize, rng: &mut Prng, mut f: F) -> bool
where
    F: FnMut(usize, &mut Prng) -> u64,
{
    for _ in 0..warmup {
        let class = (rng.u64() & 1) as usize;
        let _ = black_box(f(class, rng));
    }

    let mut c0: Vec<u64> = Vec::with_capacity(N / 2 + 1);
    let mut c1: Vec<u64> = Vec::with_capacity(N / 2 + 1);

    for _ in 0..N {
        let class = (rng.u64() & 1) as usize;
        let elapsed = f(class, rng);
        if elapsed > 0 && elapsed < MAX_CYCLES {
            if class == 0 { c0.push(elapsed); } else { c1.push(elapsed); }
        }
    }

    // 상위 CROP% 이상값 제거 (OS 인터럽트 / 캐시 미스 필터링)
    c0.sort_unstable();
    c1.sort_unstable();
    c0.truncate((c0.len() as f64 * (1.0 - CROP)) as usize);
    c1.truncate((c1.len() as f64 * (1.0 - CROP)) as usize);

    let mut tt = Ttest::default();
    c0.iter().for_each(|&v| tt.push(0, v as f64));
    c1.iter().for_each(|&v| tt.push(1, v as f64));

    let t = tt.t();
    let a = t.abs();
    let s = if a < T_WARN { "PASS" } else if a < T_FAIL { "WARN" } else { "FAIL" };
    println!("  {:<48} t={:+8.3}  [{s}]", label, t);
    a < T_WARN
}

fn main() {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 ^ d.as_secs().wrapping_mul(0x517cc1b727220a95))
        .unwrap_or(0xdeadbeef_cafef00d);

    let warmup = parse_args();
    let mut rng = Prng::from_seed(seed);
    let mut ok = true;
    let sep = "─".repeat(68);

    println!("DudeCT 타이밍 분석 ─ entlib-native-constant-time");
    println!(
        "N={N}  warmup={warmup}  crop={crop_pct:.0}%  PASS=|t|<{T_WARN}  FAIL=|t|≥{T_FAIL}",
        crop_pct = CROP * 100.0,
    );
    println!("{sep}");

    // ─── u64 ──────────────────────────────────────────────────────────────────
    // 양 클래스 모두 동일한 횟수의 PRNG 호출 수행 (비대칭 PRNG 호출은
    // CPU 마이크로-아키텍처 상태 편차를 유발하여 위음성 DudeCT FAIL의 원인이 됨)
    println!("\n[u64 :: ConstantTimeEq / ct_ne / ct_is_ge]");
    ok &= dudect("ct_eq   equal vs. unequal", warmup, &mut rng, |cls, rng| {
        let a = rng.u64();
        let r = rng.u64(); // 양 클래스 동일하게 2회 호출
        let b = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_eq(&black_box(b)));
        tsc().saturating_sub(t0)
    });
    ok &= dudect("ct_ne   equal vs. unequal", warmup, &mut rng, |cls, rng| {
        let a = rng.u64();
        let r = rng.u64();
        let b = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_ne(&black_box(b)));
        tsc().saturating_sub(t0)
    });
    ok &= dudect("ct_is_ge  equal vs. random", warmup, &mut rng, |cls, rng| {
        let a = rng.u64();
        let r = rng.u64();
        // cls=0: a >= a (항상 True), cls=1: a >= r (임의 결과)
        let b = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_is_ge(&black_box(b)));
        tsc().saturating_sub(t0)
    });

    // ─── u32 ──────────────────────────────────────────────────────────────────
    println!("\n[u32 :: ConstantTimeEq]");
    ok &= dudect("ct_eq   equal vs. unequal", warmup, &mut rng, |cls, rng| {
        let a = rng.u64() as u32;
        let r = rng.u64() as u32;
        let b: u32 = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_eq(&black_box(b)));
        tsc().saturating_sub(t0)
    });

    // ─── u8 ───────────────────────────────────────────────────────────────────
    println!("\n[u8 :: ConstantTimeEq]");
    ok &= dudect("ct_eq   equal vs. unequal", warmup, &mut rng, |cls, rng| {
        let a = rng.u64() as u8;
        let r = rng.u64() as u8;
        let b: u8 = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_eq(&black_box(b)));
        tsc().saturating_sub(t0)
    });

    // ─── ConstantTimeSelect ───────────────────────────────────────────────────
    // Choice를 외부에서 직접 생성할 수 없으므로 ct_eq로 0xFF / 0x00을 유도
    println!("\n[u64 :: ConstantTimeSelect]");
    ok &= dudect("ct_select  choice=0xFF vs 0x00", warmup, &mut rng, |cls, rng| {
        let a = rng.u64();
        let b = rng.u64();
        // cls=0 → 0u8==0u8 → Choice(0xFF), cls=1 → 1u8==0u8 → Choice(0x00)
        let choice = black_box(cls as u8).ct_eq(&black_box(0u8));
        let t0 = tsc();
        let _ = black_box(<u64 as ConstantTimeSelect>::ct_select(
            &black_box(a),
            &black_box(b),
            black_box(choice),
        ));
        tsc().saturating_sub(t0)
    });

    // ─── ConstantTimeSwap ─────────────────────────────────────────────────────
    println!("\n[u64 :: ConstantTimeSwap]");
    ok &= dudect("ct_swap  swap vs. noop", warmup, &mut rng, |cls, rng| {
        let mut a = rng.u64();
        let mut b = rng.u64();
        let choice = black_box(cls as u8).ct_eq(&black_box(0u8));
        let t0 = tsc();
        <u64 as ConstantTimeSwap>::ct_swap(
            black_box(&mut a),
            black_box(&mut b),
            black_box(choice),
        );
        let t1 = tsc();
        let _ = black_box((a, b));
        t1.saturating_sub(t0)
    });

    // ─── ConstantTimeIsZero ───────────────────────────────────────────────────
    println!("\n[u64 :: ConstantTimeIsZero]");
    ok &= dudect("ct_is_zero  0 vs. nonzero", warmup, &mut rng, |cls, rng| {
        let r = rng.u64(); // 양 클래스 동일하게 1회 호출
        let v: u64 = if cls == 0 { 0 } else { r | 1 };
        let t0 = tsc();
        let _ = black_box(black_box(v).ct_is_zero());
        tsc().saturating_sub(t0)
    });

    // ─── ConstantTimeIsNegative (u64 MSB) ────────────────────────────────────
    println!("\n[u64 :: ConstantTimeIsNegative]");
    ok &= dudect("ct_is_negative  MSB=1 vs. MSB=0", warmup, &mut rng, |cls, rng| {
        let r = rng.u64();
        let v: u64 = if cls == 0 {
            r | 0x8000_0000_0000_0000   // MSB 강제 설정
        } else {
            r & 0x7fff_ffff_ffff_ffff   // MSB 강제 소거
        };
        let t0 = tsc();
        let _ = black_box(black_box(v).ct_is_negative());
        tsc().saturating_sub(t0)
    });

    // ─── i64 ──────────────────────────────────────────────────────────────────
    println!("\n[i64 :: ConstantTimeEq / ct_is_ge / ct_is_negative]");
    ok &= dudect("ct_eq   equal vs. unequal", warmup, &mut rng, |cls, rng| {
        let a = rng.u64() as i64;
        let r = rng.u64() as i64;
        let b: i64 = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_eq(&black_box(b)));
        tsc().saturating_sub(t0)
    });
    ok &= dudect("ct_is_ge  equal vs. random", warmup, &mut rng, |cls, rng| {
        let a = rng.u64() as i64;
        let r = rng.u64() as i64;
        let b: i64 = if cls == 0 { a } else { r };
        let t0 = tsc();
        let _ = black_box(black_box(a).ct_is_ge(&black_box(b)));
        tsc().saturating_sub(t0)
    });
    ok &= dudect("ct_is_negative  MSB=1 vs. MSB=0", warmup, &mut rng, |cls, rng| {
        let r = rng.u64();
        // 부호 없는 비트로 MSB 제어 후 i64로 해석
        let v: i64 = if cls == 0 {
            (r | 0x8000_0000_0000_0000) as i64   // 항상 음수
        } else {
            (r & 0x7fff_ffff_ffff_ffff) as i64   // 항상 양수
        };
        let t0 = tsc();
        let _ = black_box(black_box(v).ct_is_negative());
        tsc().saturating_sub(t0)
    });

    println!("\n{sep}");
    if ok {
        println!("결과: PASS ─ 모든 연산이 상수-시간 기준을 충족합니다.");
    } else {
        eprintln!("결과: FAIL ─ 타이밍 의존성이 검출된 연산이 존재합니다.");
        std::process::exit(1);
    }
}
