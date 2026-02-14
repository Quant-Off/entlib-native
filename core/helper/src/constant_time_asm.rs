//! 아키텍처별 인라인 어셈블리 기반 상수-시간 프리미티브
//!
//! # Author
//! Q. T. Felix
//!
//! | 티어 | 아키텍처 | 타입 | 방식 |
//! |------|----------|------|------|
//! | 1 (Full ASM) | x86_64, aarch64 | u32, u64 | 전체 인라인 어셈블리 |
//! | 2 (Barrier) | x86_64, aarch64 | u8, u16, u128 | ASM 배리어 + Rust 비트 로직 |
//! | 3 (Fallback) | 기타 | 전체 | `black_box` 폴백 |

/// 아키텍처별 인라인 어셈블리 기반 상수-시간 프리미티브 트레이트
///
/// 이 트레이트는 조건 분기(branch)를 사용하지 않고 비트 연산과 인라인 어셈블리를 통해
/// 상수 시간(Constant-Time)에 동작하는 저수준 연산들을 정의합니다.
/// 암호학적 연산이나 사이드 채널 공격(side-channel attack)에 민감한 로직을 구현할 때 사용됩니다.
///
/// # Usage
/// ```rust
/// use entlib_native_helper::constant_time_asm::CtPrimitive;
///
/// let a = 10u32;
/// let b = 20u32;
///
/// // 두 값이 같은지 비교 (같으면 !0, 다르면 0 반환)
/// let mask = a.ct_equal(b);
/// assert_eq!(mask, 0);
///
/// // 마스크를 이용한 값 선택 (Constant-Time MUX)
/// // mask가 0이므로 b가 선택됨
/// let selected = a.ct_mux(b, mask);
/// assert_eq!(selected, b);
/// ```
///
/// # Safety
/// 이 트레이트의 구현체들은 컴파일러 최적화를 방지하기 위해 `core::hint::black_box` 또는
/// 인라인 어셈블리(`asm!`)를 사용합니다. 하지만 특정 아키텍처나 컴파일러 버전에서는
/// 의도치 않은 최적화가 발생할 수 있으므로, 중요한 보안 로직에 사용할 경우
/// 생성된 어셈블리 코드를 검증하는 것이 좋습니다.
pub trait CtPrimitive: Copy + Sized {
    /// 최적화 배리어: 컴파일러가 값에 대한 추론을 불가능하게 만듦
    fn ct_fence(self) -> Self;
    /// != 0 → all 1s, == 0 → 0
    fn ct_nonzero(self) -> Self;
    /// == 0 → all 1s, != 0 → 0
    fn ct_zero(self) -> Self;
    /// MSB == 1 → all 1s, MSB == 0 → 0
    fn ct_negative(self) -> Self;
    /// self == other → all 1s, self != other → 0
    fn ct_equal(self, other: Self) -> Self;
    /// self != other → all 1s, self == other → 0
    fn ct_not_equal(self, other: Self) -> Self;
    /// mask == all 1s → self, mask == 0 → other
    fn ct_mux(self, other: Self, mask: Self) -> Self;
}

//
// 공통 매크로 - start
//

/// ct_fence 기반 Rust 비트 로직으로 나머지 연산을 구현합니다.
/// ct_fence는 호출 측에서 별도 구현해야 합니다.
macro_rules! impl_ct_rust_ops {
    ($t:ty) => {
        #[inline(always)]
        fn ct_nonzero(self) -> Self {
            const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;
            let val = self.ct_fence();
            let or_neg = val | val.wrapping_neg();
            let msb = or_neg >> (BITS - 1);
            (msb & 1).wrapping_neg()
        }

        #[inline(always)]
        fn ct_zero(self) -> Self {
            !self.ct_nonzero()
        }

        #[inline(always)]
        fn ct_negative(self) -> Self {
            const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;
            let val = self.ct_fence();
            let msb = val >> (BITS - 1);
            (msb & 1).wrapping_neg()
        }

        #[inline(always)]
        fn ct_equal(self, other: Self) -> Self {
            const BITS: u32 = (core::mem::size_of::<$t>() * 8) as u32;
            let a = self.ct_fence();
            let b = other.ct_fence();
            let diff = a ^ b;
            let diff_or_neg = diff | diff.wrapping_neg();
            let non_zero_bit = (diff_or_neg >> (BITS - 1)) & 1;
            (non_zero_bit ^ 1).wrapping_neg()
        }

        #[inline(always)]
        fn ct_not_equal(self, other: Self) -> Self {
            !self.ct_equal(other)
        }

        #[inline(always)]
        fn ct_mux(self, other: Self, mask: Self) -> Self {
            let a = self.ct_fence();
            let b = other.ct_fence();
            let m = mask.ct_fence();
            b ^ (m & (a ^ b))
        }
    };
}

/// 다른 프리미티브 타입으로 위임합니다 (signed → unsigned, usize → u64/u32 등).
macro_rules! impl_ct_delegate {
    ($from:ty, $to:ty) => {
        impl CtPrimitive for $from {
            #[inline(always)]
            fn ct_fence(self) -> Self {
                (self as $to).ct_fence() as Self
            }
            #[inline(always)]
            fn ct_nonzero(self) -> Self {
                (self as $to).ct_nonzero() as Self
            }
            #[inline(always)]
            fn ct_zero(self) -> Self {
                (self as $to).ct_zero() as Self
            }
            #[inline(always)]
            fn ct_negative(self) -> Self {
                (self as $to).ct_negative() as Self
            }
            #[inline(always)]
            fn ct_equal(self, other: Self) -> Self {
                (self as $to).ct_equal(other as $to) as Self
            }
            #[inline(always)]
            fn ct_not_equal(self, other: Self) -> Self {
                (self as $to).ct_not_equal(other as $to) as Self
            }
            #[inline(always)]
            fn ct_mux(self, other: Self, mask: Self) -> Self {
                (self as $to).ct_mux(other as $to, mask as $to) as Self
            }
        }
    };
}

/// x86_64 전체 인라인 어셈블리 (u32, u64)
///
/// | 연산 | 명령어 시퀀스 | 설명 |
/// |------|-------------|------|
/// | ct_fence | (빈 asm) | 값 배리어 |
/// | ct_nonzero | neg → sbb | CF 기반 마스크 생성 |
/// | ct_zero | neg → sbb → not | nonzero의 반전 |
/// | ct_negative | shr → neg | MSB 추출 후 확장 |
/// | ct_equal | xor → neg → sbb → not | 차이=0 검사 |
/// | ct_not_equal | xor → neg → sbb | 차이≠0 검사 |
/// | ct_mux | xor → and → xor | XOR-swap 선택 |
#[cfg(target_arch = "x86_64")]
macro_rules! impl_ct_full_asm_x86_64 {
    ($t:ty, $mod:literal, $shift:literal) => {
        impl CtPrimitive for $t {
            #[inline(always)]
            fn ct_fence(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("/* {0", $mod, "} */"),
                        inout(reg) val,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_nonzero(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("neg {val", $mod, "}"),
                        concat!("sbb {val", $mod, "}, {val", $mod, "}"),
                        val = inout(reg) val,
                        options(nomem, nostack)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_zero(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("neg {val", $mod, "}"),
                        concat!("sbb {val", $mod, "}, {val", $mod, "}"),
                        concat!("not {val", $mod, "}"),
                        val = inout(reg) val,
                        options(nomem, nostack)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_negative(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("shr {val", $mod, "}, ", $shift),
                        concat!("neg {val", $mod, "}"),
                        val = inout(reg) val,
                        options(nomem, nostack)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_equal(self, other: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("xor {a", $mod, "}, {b", $mod, "}"),
                        concat!("neg {a", $mod, "}"),
                        concat!("sbb {a", $mod, "}, {a", $mod, "}"),
                        concat!("not {a", $mod, "}"),
                        a = inout(reg) a,
                        b = in(reg) other,
                        options(nomem, nostack)
                    );
                }
                a
            }

            #[inline(always)]
            fn ct_not_equal(self, other: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("xor {a", $mod, "}, {b", $mod, "}"),
                        concat!("neg {a", $mod, "}"),
                        concat!("sbb {a", $mod, "}, {a", $mod, "}"),
                        a = inout(reg) a,
                        b = in(reg) other,
                        options(nomem, nostack)
                    );
                }
                a
            }

            #[inline(always)]
            fn ct_mux(self, other: Self, mask: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("xor {a", $mod, "}, {b", $mod, "}"),
                        concat!("and {a", $mod, "}, {mask", $mod, "}"),
                        concat!("xor {a", $mod, "}, {b", $mod, "}"),
                        a = inout(reg) a,
                        b = in(reg) other,
                        mask = in(reg) mask,
                        options(nomem, nostack)
                    );
                }
                a
            }
        }
    };
}

#[cfg(target_arch = "x86_64")]
impl_ct_full_asm_x86_64!(u64, "", "63");
#[cfg(target_arch = "x86_64")]
impl_ct_full_asm_x86_64!(u32, ":e", "31");

/// aarch64 전체 인라인 어셈블리 (u32, u64)
///
/// | 연산 | 명령어 시퀀스 | 설명 |
/// |------|-------------|------|
/// | ct_fence | (빈 asm) | 값 배리어 |
/// | ct_nonzero | subs zr, zr, val → sbc val, zr, zr | 캐리 기반 마스크 |
/// | ct_zero | 위 + mvn | nonzero 반전 |
/// | ct_negative | lsr → neg | MSB 추출 후 확장 |
/// | ct_equal | eor → subs → sbc → mvn | |
/// | ct_not_equal | eor → subs → sbc | |
/// | ct_mux | eor → and → eor | |
#[cfg(target_arch = "aarch64")]
macro_rules! impl_ct_full_asm_aarch64 {
    ($t:ty, $zr:literal, $shift:literal, $mod:literal) => {
        impl CtPrimitive for $t {
            #[inline(always)]
            fn ct_fence(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("/* {0", $mod, "} */"),
                        inout(reg) val,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_nonzero(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("subs ", $zr, ", ", $zr, ", {val", $mod, "}"),
                        concat!("sbc {val", $mod, "}, ", $zr, ", ", $zr),
                        val = inout(reg) val,
                        options(nomem, nostack)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_zero(self) -> Self {
                let mut val = self;
                unsafe {
                    core::arch::asm!(
                        concat!("subs ", $zr, ", ", $zr, ", {val", $mod, "}"),
                        concat!("sbc {val", $mod, "}, ", $zr, ", ", $zr),
                        concat!("mvn {val", $mod, "}, {val", $mod, "}"),
                        val = inout(reg) val,
                        options(nomem, nostack)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_negative(self) -> Self {
                let mut val = self;
                unsafe {
                    // NOTE: 이 로직에서 lsr 후 neg 을 통해 마스크를 확장하는 로직을 사용함
                    // 이건 완벽하다고 생각하지만, C/C++ 등 타 언어의 산술 시프트 동작과
                    // 혼동될 수 있다는걸 이제야 깨달음. C/C++ 랑 혼동하지 마세요!!!!!
                    // 쉽게 말해 논리적 우측 시프트(lsr) 사용됨
                    core::arch::asm!(
                        concat!("lsr {val", $mod, "}, {val", $mod, "}, #", $shift),
                        concat!("neg {val", $mod, "}, {val", $mod, "}"),
                        val = inout(reg) val,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                val
            }

            #[inline(always)]
            fn ct_equal(self, other: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("eor {a", $mod, "}, {a", $mod, "}, {b", $mod, "}"),
                        concat!("subs ", $zr, ", ", $zr, ", {a", $mod, "}"),
                        concat!("sbc {a", $mod, "}, ", $zr, ", ", $zr),
                        concat!("mvn {a", $mod, "}, {a", $mod, "}"),
                        a = inout(reg) a,
                        b = in(reg) other,
                        options(nomem, nostack)
                    );
                }
                a
            }

            #[inline(always)]
            fn ct_not_equal(self, other: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("eor {a", $mod, "}, {a", $mod, "}, {b", $mod, "}"),
                        concat!("subs ", $zr, ", ", $zr, ", {a", $mod, "}"),
                        concat!("sbc {a", $mod, "}, ", $zr, ", ", $zr),
                        a = inout(reg) a,
                        b = in(reg) other,
                        options(nomem, nostack)
                    );
                }
                a
            }

            #[inline(always)]
            fn ct_mux(self, other: Self, mask: Self) -> Self {
                let mut a = self;
                unsafe {
                    core::arch::asm!(
                        concat!("eor {a", $mod, "}, {a", $mod, "}, {b", $mod, "}"),
                        concat!("and {a", $mod, "}, {a", $mod, "}, {mask", $mod, "}"),
                        concat!("eor {a", $mod, "}, {a", $mod, "}, {b", $mod, "}"),
                        a = inout(reg) a,
                        b = in(reg) other,
                        mask = in(reg) mask,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                a
            }
        }
    };
}

#[cfg(target_arch = "aarch64")]
impl_ct_full_asm_aarch64!(u64, "xzr", "63", ":x");
#[cfg(target_arch = "aarch64")]
impl_ct_full_asm_aarch64!(u32, "wzr", "31", ":w");

//
// ASM 배리어 + Rust 비트 로직 (u8, u16, u128) - start
//

// --- u8: x86_64 (reg_byte) ---
#[cfg(target_arch = "x86_64")]
impl CtPrimitive for u8 {
    #[inline(always)]
    fn ct_fence(self) -> Self {
        let mut val = self;
        unsafe {
            core::arch::asm!(
                "/* {0} */",
                inout(reg_byte) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val
    }

    impl_ct_rust_ops!(u8);
}

// --- u8: aarch64 (u32 승격) ---
#[cfg(target_arch = "aarch64")]
impl CtPrimitive for u8 {
    #[inline(always)]
    fn ct_fence(self) -> Self {
        let mut val = self as u32;
        unsafe {
            core::arch::asm!(
                "/* {0:w} */",
                inout(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val as u8
    }

    impl_ct_rust_ops!(u8);
}

// --- u16: x86_64 (reg) ---
#[cfg(target_arch = "x86_64")]
impl CtPrimitive for u16 {
    #[inline(always)]
    fn ct_fence(self) -> Self {
        let mut val = self;
        unsafe {
            core::arch::asm!(
                "/* {0:x} */",
                inout(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val
    }

    impl_ct_rust_ops!(u16);
}

// --- u16: aarch64 (u32 승격) ---
#[cfg(target_arch = "aarch64")]
impl CtPrimitive for u16 {
    #[inline(always)]
    fn ct_fence(self) -> Self {
        let mut val = self as u32;
        unsafe {
            core::arch::asm!(
                "/* {0:w} */",
                inout(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val as u16
    }

    impl_ct_rust_ops!(u16);
}

// --- u128: x86_64/aarch64 (u64 분할) ---
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl CtPrimitive for u128 {
    #[inline(always)]
    fn ct_fence(self) -> Self {
        let mut lo = self as u64;
        let mut hi = (self >> 64) as u64;
        unsafe {
            // NOTE: 구글링해보니 aarch64에서는 :x가 64비트를 명시하고, x86_64에서는 무시되거나 호환된다고 함
            // 아키텍처 공통으로 사용할 때 크기 경고를 방지하기 위해 각각 명시합니다
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "/* {0:x} {1:x} */",
                inout(reg) lo,
                inout(reg) hi,
                options(nomem, nostack, preserves_flags)
            );

            #[cfg(target_arch = "x86_64")]
            core::arch::asm!(
                "/* {0} {1} */",
                inout(reg) lo,
                inout(reg) hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        (hi as u128) << 64 | (lo as u128)
    }

    impl_ct_rust_ops!(u128);
}

//
// Tier 3: Fallback (x86_64/aarch64 이외 아키텍처) - start
//

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
macro_rules! impl_ct_fallback {
    ($($t:ty),+) => {
        $(
            impl CtPrimitive for $t {
                #[inline(always)]
                fn ct_fence(self) -> Self {
                    core::hint::black_box(self)
                }

                impl_ct_rust_ops!($t);
            }
        )+
    };
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl_ct_fallback!(u8, u16, u32, u64, u128);

//
// usize 위임 (포인터 폭에 따라 u64 또는 u32로) - start
//

#[cfg(target_pointer_width = "64")]
impl_ct_delegate!(usize, u64);

#[cfg(target_pointer_width = "32")]
impl_ct_delegate!(usize, u32);

//
// Signed 타입 위임 (unsigned 대응 타입으로 캐스트, 비트 패턴 동일) - start
//

impl_ct_delegate!(i8, u8);
impl_ct_delegate!(i16, u16);
impl_ct_delegate!(i32, u32);
impl_ct_delegate!(i64, u64);
impl_ct_delegate!(i128, u128);

#[cfg(target_pointer_width = "64")]
impl_ct_delegate!(isize, u64);

#[cfg(target_pointer_width = "32")]
impl_ct_delegate!(isize, u32);
