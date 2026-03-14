#![cfg(test)]
#![cfg(target_os = "linux")]
#![cfg(feature = "valgrind_taint_audit")]

use entlib_native_constant_time::choice::Choice;
use entlib_native_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use core::arch::asm;

// 하이퍼 콜 상수
// Memcheck Tool ID: 'M'(77) << 24 | 'C'(67) << 16 = 0x4d430000
const VALGRIND_MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const VALGRIND_MAKE_MEM_DEFINED: usize   = 0x4d43_0002;
const VALGRIND_RUNNING_ON_VALGRIND: usize = 0x1001;

/// x86_64 아키텍처 전용 Valgrind 하이퍼콜 주입 (Zero-Dependency)
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn do_valgrind_request(request: usize, arg1: usize, arg2: usize) -> usize {
    let mut result: usize;
    // Valgrind가 가로채는 특수 명령어 시퀀스 (Magic Sequence)
    asm!(
    "rol rdi, 3",
    "rol rdi, 13",
    "rol rdi, 61",
    "rol rdi, 51",
    "xchg rbx, rbx",
    inout("rax") request => result,
    in("rdi") arg1,
    in("rsi") arg2,
    out("rdx") _,
    out("rcx") _,
    out("r8") _,
    out("r9") _,
    out("r10") _,
    out("r11") _,
    options(nostack, preserves_flags)
    );
    result
}

/// 타 아키텍처(aarch64 등) 빌드 호환성 유지 (Fallback)
/// (aarch64에서도 Valgrind 검증이 필수라면 해당 아키텍처의 ror 시퀀스 추가 필요)
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
unsafe fn do_valgrind_request(_request: usize, _arg1: usize, _arg2: usize) -> usize {
    0 // Native 환경에서는 안전하게 No-op 처리
}

#[inline(always)]
fn is_running_on_valgrind() -> bool {
    unsafe { do_valgrind_request(VALGRIND_RUNNING_ON_VALGRIND, 0, 0) > 0 }
}

/// 비밀 데이터를 오염(Taint) 처리합니다.
unsafe fn taint_memory<T>(data: &T) {
    if is_running_on_valgrind() {
        do_valgrind_request(
            VALGRIND_MAKE_MEM_UNDEFINED,
            data as *const T as usize,
            core::mem::size_of::<T>(),
        );
    }
}

/// 비밀 데이터의 오염(Taint) 상태를 해제합니다.
unsafe fn untaint_memory<T>(data: &T) {
    if is_running_on_valgrind() {
        do_valgrind_request(
            VALGRIND_MAKE_MEM_DEFINED,
            data as *const T as usize,
            core::mem::size_of::<T>(),
        );
    }
}

#[test]
fn audit_taint_flow_ct_eq() {
    let a: u64 = 0xDEADBEEFC0DECAFE;
    let b: u64 = 0xDEADBEEFC0DECAFE;

    unsafe {
        taint_memory(&a);
        taint_memory(&b);
    }

    let result = a.ct_eq(&b);

    unsafe {
        untaint_memory(&a);
        untaint_memory(&b);
        untaint_memory(&result);
    }

    assert_eq!(result.unwrap_u8(), 0xFF);
}

#[test]
fn audit_taint_flow_ct_select() {
    let a: u32 = 0x11111111;
    let b: u32 = 0x22222222;
    let choice = unsafe { core::mem::transmute::<u8, Choice>(0xFF) };

    unsafe {
        taint_memory(&a);
        taint_memory(&b);
        taint_memory(&choice);
    }

    let selected = u32::ct_select(&a, &b, choice);

    unsafe {
        untaint_memory(&a);
        untaint_memory(&b);
        untaint_memory(&choice);
        untaint_memory(&selected);
    }

    assert_eq!(selected, 0x11111111);
}