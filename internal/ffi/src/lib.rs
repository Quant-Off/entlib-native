pub mod base64_ffi;
mod chacha20_ffi;
mod rng_ffi; // todo; 보안강화 및 검증
pub mod secure_buffer_ffi;
pub mod sha2_ffi;
pub mod sha3_ffi;

/// ffi 작업 중 발생할 수 있는 상태 코드 (status code)
#[repr(C)]
pub enum FFIStatus {
    Success = 0,
    NullPointerError = -1,
}

//
// no_std 유지 - start
//
// 아래 방법은 no_std를 유지하는 해결책이지만, Java 애플리케이션과 상호 작용하는 환경은 이미
// 범용 운영체제의 스레드 모델과 가상 메모리 관리 시스템 위에서 동작함. 특수한 임베디드 하드웨어
// 타겟팅이 목적이 아니라면, no_std를 해제하고 Rust의 표준 라이브러리(std)를 활용하는 것이
// 메모리 효율 측면에서 시스템적 안정성을 극대화하는 데 유리함
//
// #![no_std]
// extern crate alloc;
//
// // 스레드 안전과 메모리 안정성을 위해 libc 기반 글로벌 allocator 사용
// use libc_alloc::LibcAlloc;
//
// #[global_allocator]
// static ALLOCATOR: LibcAlloc = LibcAlloc;
//
// #[cfg(not(test))]
// #[panic_handler]
// fn panic(_info: &internal::panic::PanicInfo) -> ! {
//     // 민감 데이터 유출 방지를 위해 즉시 해제
//     unsafe {
//         libc::abort();
//     }
// }
//
// no_std 유지 - end
//
