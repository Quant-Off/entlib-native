#![cfg(test)]
#![cfg(target_os = "linux")]

use valgrind_request::running_on_valgrind;
use entlib_native_newer_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use entlib_native_newer_constant_time::choice::Choice;

/// [보안 통제] Memcheck Client Request 연동 (ctgrind 기법)
/// Rust 생태계에서 누락된 Memcheck 매크로를 FFI를 통해 강제 바인딩합니다.
/// C 헤더 `<valgrind/memcheck.h>`의 기능을 시스템 레벨에서 직접 호출합니다.
extern "C" {
    // 메모리 영역을 '초기화되지 않음(Tainted)' 상태로 마킹하여 오염 추적 시작
    fn VALGRIND_MAKE_MEM_UNDEFINED(_qzz_addr: *const u8, _qzz_len: usize) -> usize;
    // 메모리 영역을 '초기화됨(Untainted)' 상태로 복구하여 정상 분기 허용
    fn VALGRIND_MAKE_MEM_DEFINED(_qzz_addr: *const u8, _qzz_len: usize) -> usize;
}

/// 비밀 데이터를 오염(Taint) 처리합니다.
unsafe fn taint_memory<T>(data: &T) {
    if running_on_valgrind() > 0 {
        VALGRIND_MAKE_MEM_UNDEFINED(
            data as *const T as *const u8,
            core::mem::size_of::<T>(),
        );
    }
}

/// 비밀 데이터의 오염(Taint) 상태를 해제합니다.
unsafe fn untaint_memory<T>(data: &T) {
    if running_on_valgrind() > 0 {
        VALGRIND_MAKE_MEM_DEFINED(
            data as *const T as *const u8,
            core::mem::size_of::<T>(),
        );
    }
}

#[test]
fn audit_taint_flow_ct_eq() {
    // 1. 테스트 데이터 준비
    let a: u64 = 0xDEADBEEFC0DECAFE;
    let b: u64 = 0xDEADBEEFC0DECAFE; // a와 동일

    unsafe {
        // 2. 입력값을 Tainted(초기화되지 않음) 상태로 전환
        // 이 시점 이후 a와 b의 값이 조건 분기(if/match)에 사용되면 Valgrind가 에러를 발생시킴
        taint_memory(&a);
        taint_memory(&b);
    }

    // 3. 상수-시간 연산 수행 (분기가 발생하지 않아야 함)
    // 연산 내부에서 비트 마스킹만 수행하므로 Memcheck 에러가 발생해서는 안 됨
    let result = a.ct_eq(&b);

    unsafe {
        // 4. 연산 결과 및 원본 데이터의 Taint 상태 해제
        // 테스트 프레임워크의 assert! 매크로는 내부적으로 분기를 사용하므로,
        // 검증이 완료된 후에는 반드시 상태를 복구해야 False Positive를 방지할 수 있음
        untaint_memory(&a);
        untaint_memory(&b);
        untaint_memory(&result);
    }

    // 5. 무결성 검증
    assert_eq!(result.unwrap_u8(), 0xFF);
}

#[test]
fn audit_taint_flow_ct_select() {
    let a: u32 = 0x11111111;
    let b: u32 = 0x22222222;
    // 내부적으로 0xFF를 가진 Choice 생성 (True 조건)
    let choice = unsafe { core::mem::transmute::<u8, Choice>(0xFF) };

    unsafe {
        // 2. 조건 마스크(choice)를 포함한 모든 입력을 Tainted 상태로 전환
        taint_memory(&a);
        taint_memory(&b);
        taint_memory(&choice);
    }

    // 3. 상수-시간 조건부 선택 수행
    let selected = u32::ct_select(&a, &b, choice);

    unsafe {
        // 4. Taint 상태 해제
        untaint_memory(&a);
        untaint_memory(&b);
        untaint_memory(&choice);
        untaint_memory(&selected);
    }

    assert_eq!(selected, 0x11111111);
}