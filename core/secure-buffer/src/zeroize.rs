use core::arch::asm;
use core::sync::atomic::{Ordering, compiler_fence, fence};

/// 원시 포인터 기반의 물리적 메모리 소거 트레이트
pub trait SecureZeroize {
    /// 할당된 전체 용량(capacity)에 대해 소거를 수행합니다.
    ///
    /// # Safety
    /// `ptr`은 유효한 메모리여야 하며, `capacity` 범위를 초과하여 접근하지 않아야 합니다.
    unsafe fn zeroize_raw(ptr: *mut u8, capacity: usize);
}

pub struct Zeroizer;

impl SecureZeroize for Zeroizer {
    #[inline(never)]
    unsafe fn zeroize_raw(ptr: *mut u8, capacity: usize) {
        if ptr.is_null() || capacity == 0 {
            return;
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            // 하드웨어 수준의 고속 메모리 초기화 (DSE 원천 차단)
            // rep stosb 명령어는 CPU 마이크로코드에서 가장 효율적으로 0을 채우도록 최적화됨
            asm!(
            "rep stosb",
            inout("rcx") capacity => _,
            inout("rdi") ptr => _,
            in("al") 0u8,
            options(nostack, preserves_flags)
            );

            // Cache Line Flush (clflush) 적용
            // 캐시 라인에 남아있는 0(Zero) 데이터를 강제로 DRAM으로 밀어내어 물리적 덮어쓰기 수행
            let mut flush_ptr = ptr as usize;
            let end_ptr = flush_ptr + capacity;

            // x86_64 아키텍처의 표준 캐시 라인 크기 (64 Bytes)
            while flush_ptr < end_ptr {
                asm!(
                "clflush [{0}]",
                in(reg) flush_ptr,
                options(readonly, nostack, preserves_flags)
                );
                flush_ptr += 64;
            }

            // 메모리 배리어: 모든 메모리 저장 및 플러시 작업이 완료될 때까지 실행 강제
            asm!("mfence", options(nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            // ARM 기반 (서버/임베디드) 환경을 위한 소거 루틴
            let mut current_ptr = ptr as usize;
            let end_ptr = current_ptr + capacity;

            // 메모리 초기화 루틴
            while current_ptr < end_ptr {
                core::ptr::write_volatile(current_ptr as *mut u8, 0);
                current_ptr += 1;
            }

            // Data Cache Clean and Invalidate (dc civac)
            let mut flush_ptr = ptr as usize;
            // AArch64의 캐시 라인 크기는 시스템마다 다를 수 있으나 통상 64바이트를 기준으로 함
            while flush_ptr < end_ptr {
                asm!(
                "dc civac, {0}",
                in(reg) flush_ptr,
                options(nostack, preserves_flags)
                );
                flush_ptr += 64;
            }

            // 데이터 동기화 배리어
            asm!("dsb sy", options(nostack, preserves_flags));
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        unsafe {
            // 미지원 아키텍처를 위한 안전한 Fallback (기존 로직 유지)
            let mut byte_ptr = ptr;
            for _ in 0..capacity {
                core::ptr::write_volatile(byte_ptr, 0);
                byte_ptr = byte_ptr.add(1);
            }
        }

        // 컴파일러 및 하드웨어 파이프라인 동기화
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }
}
