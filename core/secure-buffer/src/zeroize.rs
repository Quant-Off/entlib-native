use core::sync::atomic::{Ordering, compiler_fence, fence};

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn get_cache_line_size() -> usize {
    // CPUID Leaf 1을 호출하여 ebx 레지스터에서 clflush 크기 추출
    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(1);
        let clflush_size = ((cpuid.ebx >> 8) & 0xFF) as usize * 8;
        // CPUID 실패 또는 비정상 반환 시 안전한 기본값(Fallback)으로 64바이트 반환
        if clflush_size == 0 { 64 } else { clflush_size }
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn get_cache_line_size() -> usize {
    let ctr_el0: u64;
    unsafe {
        // 시스템 레지스터 CTR_EL0 (Cache Type Register) 직접 조회
        core::arch::asm!(
        "mrs {}, ctr_el0",
        out(reg) ctr_el0,
        options(nomem, nostack, preserves_flags)
        );
    }
    // DminLine (bits [19:16]): 가장 작은 데이터 캐시 라인 크기의 로그(Base 2) 값
    let dminline = (ctr_el0 >> 16) & 0xF;

    // 바이트 단위 크기 계산: 4 bytes (1 word) * 2^DminLine
    4 << dminline
}

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
            core::arch::asm!(
            "rep stosb",
            inout("rcx") capacity => _,
            inout("rdi") ptr => _,
            in("al") 0u8,
            options(nostack, preserves_flags)
            );

            // 하드웨어 레지스터 기반 동적 캐시 라인 크기 획득
            let cache_line_size = get_cache_line_size();

            let mut flush_ptr = ptr as usize;
            let end_ptr = flush_ptr + capacity;

            // 동적 크기를 반영한 Cache Line Flush 적용
            while flush_ptr < end_ptr {
                core::arch::asm!(
                "clflush [{0}]",
                in(reg) flush_ptr,
                options(readonly, nostack, preserves_flags)
                );
                flush_ptr += cache_line_size;
            }

            core::arch::asm!("mfence", options(nostack, preserves_flags));
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

            // AArch64 시스템 레지스터(CTR_EL0) 기반 동적 크기 획득
            let cache_line_size = get_cache_line_size();

            let mut flush_ptr = ptr as usize;
            let end_ptr = ptr as usize + capacity;

            // 동적 크기를 반영한 Data Cache Clean and Invalidate
            while flush_ptr < end_ptr {
                core::arch::asm!(
                "dc civac, {0}",
                in(reg) flush_ptr,
                options(nostack, preserves_flags)
                );
                flush_ptr += cache_line_size;
            }

            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        unsafe {
            // OS가 제공하는 네이티브 안전 소거 API
            #[cfg(all(unix, feature = "std"))]
            {
                extern "C" {
                    // OpenBSD, FreeBSD, Linux(glibc 2.25+) 등에서 지원
                    // 컴파일러 DSE 최적화를 완벽히 우회하고 메모리에 강제 반영
                    fn explicit_bzero(s: *mut core::ffi::c_void, n: usize);
                }
                explicit_bzero(ptr as *mut core::ffi::c_void, capacity);
            }

            #[cfg(all(windows, feature = "std"))]
            {
                extern "system" {
                    // Windows 커널에서 보장하는 강제 소거 로직
                    fn RtlSecureZeroMemory(
                        ptr: *mut core::ffi::c_void,
                        cnt: usize,
                    ) -> *mut core::ffi::c_void;
                }
                RtlSecureZeroMemory(ptr as *mut core::ffi::c_void, capacity);
            }

            // no_std 폐쇄 환경을 위한 Fall-back
            #[cfg(not(all(any(unix, windows), feature = "std")))]
            {
                // OS API가 부재한 베어메탈 환경에서는 기존과 같이 volatile 기반 강제 쓰기 수행
                // Q. T. Felix TODO: 해당 환경의 하드웨어(CPU) 특성에 따라 캐시 라인 플러시가 보장되지 않을 수 있다고 합니다.
                //                   thumbv6m-none-eabi 와 같은 arm 베어메탈 아키텍처에서의 연구가 필요합니다!!!!!
                let mut byte_ptr = ptr;
                for _ in 0..capacity {
                    core::ptr::write_volatile(byte_ptr, 0);
                    byte_ptr = byte_ptr.add(1);
                }
            }
        }

        // 컴파일러 및 하드웨어 파이프라인 동기화
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }
}
