#![cfg(test)]
#![cfg(target_os = "linux")]
#![cfg(feature = "valgrind_taint_audit")]

use core::arch::asm;
use core::hint::black_box;
use core::ptr::read_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_constant_time::choice::Choice;
use entlib_native_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};

const VALGRIND_MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const VALGRIND_MAKE_MEM_DEFINED: usize = 0x4d43_0002;
const VALGRIND_RUNNING_ON_VALGRIND: usize = 0x1001;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn do_valgrind_request(request: usize, arg1: usize, arg2: usize) -> usize {
    let args: [usize; 6] = [request, arg1, arg2, 0, 0, 0];
    let mut result: usize;

    black_box(args.as_ptr());
    compiler_fence(Ordering::SeqCst);

    asm!(
    "rol rdi, 3",
    "rol rdi, 13",
    "rol rdi, 61",
    "rol rdi, 51",
    "xchg rbx, rbx",
    inout("rax") args.as_ptr() => _,
    inout("rdx") 0usize => result,
    out("rdi") _,
    out("rcx") _,
    out("r8") _,
    out("r9") _,
    out("r10") _,
    out("r11") _
    );

    compiler_fence(Ordering::SeqCst);
    result
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
unsafe fn do_valgrind_request(_request: usize, _arg1: usize, _arg2: usize) -> usize {
    0
}

#[inline(always)]
fn is_running_on_valgrind() -> bool {
    unsafe { do_valgrind_request(VALGRIND_RUNNING_ON_VALGRIND, 0, 0) > 0 }
}

unsafe fn taint_memory<T>(data: *const T) {
    if is_running_on_valgrind() {
        do_valgrind_request(
            VALGRIND_MAKE_MEM_UNDEFINED,
            data as usize,
            core::mem::size_of::<T>(),
        );
        compiler_fence(Ordering::SeqCst);
    }
}

unsafe fn untaint_memory<T>(data: *const T) {
    if is_running_on_valgrind() {
        do_valgrind_request(
            VALGRIND_MAKE_MEM_DEFINED,
            data as usize,
            core::mem::size_of::<T>(),
        );
        compiler_fence(Ordering::SeqCst);
    }
}

#[test]
fn audit_taint_flow_ct_eq() {
    // Constant Folding 방지 및 Taint Tracking 강제를 위한 mut 및 black_box 적용
    let mut a: u64 = black_box(0xDEADBEEFC0DECAFE);
    let mut b: u64 = black_box(0xDEADBEEFC0DECAFE);

    unsafe {
        taint_memory(&a);
        taint_memory(&b);
    }

    let result = a.ct_eq(&b);

    unsafe {
        untaint_memory(&a);
        untaint_memory(&b);
        untaint_memory(&result);

        // LLVM 레지스터 캐싱 무효화 및 안전한 메모리 강제 로드
        let safe_result = read_volatile(&result);
        assert_eq!(safe_result.unwrap_u8(), 0xFF);
    }
}

#[test]
fn audit_taint_flow_ct_select() {
    // Constant Folding 방지 및 Taint Tracking 강제를 위한 mut 및 black_box 적용
    let mut a: u32 = black_box(0x11111111);
    let mut b: u32 = black_box(0x22222222);
    // 안전한 생성자 패턴 유지 및 런타임 평가 강제
    let mut choice = black_box(Choice::from(black_box(1u8)));

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

        // LLVM 레지스터 캐싱 무효화 및 안전한 메모리 강제 로드
        let safe_selected = read_volatile(&selected);
        assert_eq!(safe_selected, 0x22222222);
    }
}
