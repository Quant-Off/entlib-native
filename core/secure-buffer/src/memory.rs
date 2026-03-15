use alloc::alloc::{Layout, alloc_zeroed, dealloc};

#[cfg(feature = "std")]
use std::sync::OnceLock;

/// 시스템(런타임)의 실제 페이지 크기를 반환합니다.
pub(crate) fn page_size() -> usize {
    #[cfg(feature = "std")]
    {
        static OS_PAGE_SIZE: OnceLock<usize> = OnceLock::new();
        *OS_PAGE_SIZE.get_or_init(|| {
            #[cfg(unix)]
            unsafe {
                // 커널 계층과 직접 통신하여 페이지 크기 획득
                let size = unsafe { fetch_os_page_size() };

                // 변조된 커널 응답 방어 (최소 4kb 및 2배수 확인)
                if size < 4096 || !size.is_power_of_two() {
                    panic!("Security Violation: 안전하지 않거나 변조된 OS 페이지 크기가 감지되었습니다! ({})", size);
                }
                size
            }
        })
    }

    #[cfg(not(feature = "std"))]
    {
        // Q. T. Felix NOTE: no_std 환경에서는 빌드 타임 타겟 환경 변수 또는 하드웨어 레지스터 직접 조회 방식 적용이 필요합니다
        //                   현재는 안전을 위해 최소 기준인 4096을 반환하되, 실제 환경에 맞춘 엄격한 포팅이 요구됩니다.
        4096
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
unsafe fn fetch_os_page_size() -> usize {
    let path = b"/proc/self/auxv\0";
    let fd: isize;

    // SYS_open (x86_64) / SYS_openat (aarch64)
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("syscall",
        in("rax") 2, // SYS_open
        in("rdi") path.as_ptr(),
        in("rsi") 0, // O_RDONLY
        lateout("rax") fd,
        options(nostack, preserves_flags)
        );
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("svc #0",
        in("x8") 56, // SYS_openat
        in("x0") -100isize, // AT_FDCWD
        in("x1") path.as_ptr(),
        in("x2") 0, // O_RDONLY
        in("x3") 0, // Mode
        lateout("x0") fd,
        options(nostack, preserves_flags)
        );
    }

    if fd < 0 {
        panic!("Critical Fault: 커널이 auxv를 열기 위한 원시 시스템 호출을 거부했습니다!");
    }

    let mut buf = [0usize; 64];
    let mut extracted_page_size = 0;
    let mut bytes_read: isize;

    // SYS_read 루프
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
            "syscall",
            in("rax") 0, // SYS_read
            in("rdi") fd,
            in("rsi") buf.as_mut_ptr(),
            in("rdx") buf.len() * core::mem::size_of::<usize>(),
            lateout("rax") bytes_read,
            options(nostack, preserves_flags)
            );
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!(
            "svc #0",
            in("x8") 63, // SYS_read
            in("x0") fd,
            in("x1") buf.as_mut_ptr(),
            in("x2") buf.len() * core::mem::size_of::<usize>(),
            lateout("x0") bytes_read,
            options(nostack, preserves_flags)
            );
        }

        if bytes_read <= 0 {
            break;
        }

        let count = (bytes_read as usize) / core::mem::size_of::<usize>();
        let mut i = 0;

        while i < count {
            if buf[i] == 6 {
                // 상수 AT_PAGESZ = 6
                extracted_page_size = buf[i + 1];
                break;
            }
            if buf[i] == 0 {
                // 상수 AT_NULL = 0 (auxv의 끝)
                break;
            }
            i += 2;
        }
        if extracted_page_size != 0 {
            break;
        }
    }

    // SYS_close
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
        "syscall",
        in("rax") 3, // SYS_close
        in("rdi") fd,
        lateout("rax") _,
        options(nostack, preserves_flags)
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
        "svc #0",
        in("x8") 57, // SYS_close
        in("x0") fd,
        lateout("x0") _,
        options(nostack, preserves_flags)
        );
    }

    if extracted_page_size == 0 {
        panic!(
            "Critical Fault: 프로세스 보조 벡터(auxiliary vector)에서 AT_PAGESZ를 찾을 수 없습니다!"
        );
    }

    extracted_page_size
}

/// 요청된 크기를 시스템 페이지 크기의 배수로 올림 처리합니다.
///
/// 메모리 할당 시 페이지 정렬(Page Alignment)을 보장하기 위해 사용됩니다.
fn align_to_page(size: usize) -> usize {
    let ps = page_size();
    let remainder = size % ps;
    if remainder == 0 {
        size
    } else {
        size + (ps - remainder)
    }
}

/// 보안 요구사항을 충족하는 저수준 메모리 블록입니다.
///
/// 이 구조체는 `Vec<u8>`과 달리, 메모리 할당 시점부터 보안을 고려하여 설계되었습니다.
///
/// # Features
/// 1. 페이지 정렬(Page Alignment): 메모리 시작 주소가 페이지 경계에 맞춰지도록 할당합니다.
/// 2. Zero-Initialization**: 할당된 메모리는 즉시 0으로 초기화되어, 이전 데이터(Heap Residue)의 유출을 방지합니다.
/// 3. 메모리 잠금(Memory Locking): `std` 기능 활성화 시, OS 레벨에서 메모리 페이징(Swap)을 방지합니다.
pub struct SecureMemoryBlock {
    /// 할당된 메모리의 시작 포인터
    pub ptr: *mut u8,
    /// 할당된 메모리의 총 용량 (바이트 단위, 페이지 정렬됨)
    pub capacity: usize,
    /// 메모리 할당에 사용된 레이아웃 정보 (해제 시 필요)
    pub layout: Layout,
}

impl SecureMemoryBlock {
    /// 페이지 정렬된 메모리를 할당하고, 즉시 0으로 초기화한 뒤 OS 레벨 잠금을 시도합니다.
    ///
    /// # Arguments
    /// - `size` - 필요한 메모리 크기 (바이트). 내부적으로 페이지 크기 배수로 올림 처리됩니다.
    ///
    /// # Returns
    /// - `Ok(SecureMemoryBlock)` - 할당 및 잠금 성공 시
    /// - `Err(&'static str)` - 메모리 할당 실패 또는 잠금 실패(리소스 제한 등) 시
    ///
    /// # Safety
    /// 내부적으로 `alloc_zeroed`를 사용하여 초기화되지 않은 메모리 접근(UB)을 방지합니다.
    /// 하지만 OS의 메모리 잠금 제한(RLIMIT_MEMLOCK 등)에 걸릴 경우 실패할 수 있습니다.
    pub fn allocate_locked(size: usize) -> Result<Self, &'static str> {
        let capacity = align_to_page(size);
        let ps = page_size();
        // 페이지 크기로 정렬된 레이아웃 생성
        let layout = Layout::from_size_align(capacity, ps)
            .map_err(|_| "Invalid memory layout: Size or alignment error")?;

        // 할당 시 남는 패딩 영역의 기존 heap 찌꺼기 데이터를 0으로 덮어씀 (Zero-Initialization)
        // Safety: layout이 유효하므로 alloc_zeroed 호출은 안전함
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err("Memory allocation failed: Out of memory");
        }

        #[cfg(feature = "std")]
        unsafe {
            // OS별 메모리 잠금 수행
            if !os_lock::lock_memory(ptr, capacity) {
                // 잠금 실패 시, 할당했던 메모리를 즉시 해제하고 에러 반환
                dealloc(ptr, layout);
                return Err("OS memory lock (mlock/VirtualLock) failed. Resource limit reached.");
            }
        }

        Ok(Self {
            ptr,
            capacity,
            layout,
        })
    }

    /// 메모리 잠금을 해제하고 할당을 취소(해제)하는 함수입니다.
    ///
    /// # Safety
    /// - 이 함수는 `Drop` 트레이트 구현 등에서 한 번만 호출되어야 합니다.
    /// - 이미 해제된 메모리에 대해 호출하면 Double Free 오류가 발생합니다.
    /// - 호출 전, 메모리 내용 소거는 별도로 수행되어야 합니다. (이 함수는 소거를 수행하지 않음)
    pub unsafe fn deallocate_unlocked(&self) {
        #[cfg(feature = "std")]
        // 메모리 잠금 해제 (페이지 아웃 허용)
        unsafe {
            os_lock::unlock_memory(self.ptr, self.capacity);
        }

        // 메모리 할당 해제
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

/// OS별 메모리 잠금/해제 구현 모듈
#[cfg(feature = "std")]
pub(crate) mod os_lock {
    use core::ffi::c_void;

    #[cfg(unix)]
    unsafe extern "C" {
        fn mlock(addr: *const c_void, len: usize) -> i32;
        fn munlock(addr: *const c_void, len: usize) -> i32;
    }

    #[cfg(windows)]
    extern "system" {
        fn VirtualLock(lpAddress: *const c_void, dwSize: usize) -> i32;
        fn VirtualUnlock(lpAddress: *const c_void, dwSize: usize) -> i32;
    }

    /// Unix 계열(Linux, macOS 등)에서의 메모리 잠금 구현
    ///
    /// `mlock` 시스템 콜을 사용하여 지정된 범위의 가상 주소 공간을 RAM에 고정합니다.
    /// 성공 시 `true`, 실패 시 `false`를 반환합니다.
    #[cfg(unix)]
    pub unsafe fn lock_memory(ptr: *mut u8, len: usize) -> bool {
        // 1차 잠금 시도
        if unsafe { mlock(ptr as *const c_void, len) == 0 } {
            return true;
        }

        // 1차 실패
        // os 리소스 제한 동적 해제 시도
        #[cfg(target_os = "linux")]
        {
            #[repr(C)]
            struct Rlimit {
                rlim_cur: u64,
                rlim_max: u64,
            }

            unsafe extern "C" {
                fn get_rlimit(resource: i32, rlim: *mut Rlimit) -> i32;
                fn set_rlimit(resource: i32, rlim: *const Rlimit) -> i32;
            }

            const RLIMIT_MEMLOCK: i32 = 8;
            const RLIM_INFINITY: u64 = u64::MAX;

            let mut rlim = Rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            unsafe {
                if get_rlimit(RLIMIT_MEMLOCK, &mut rlim) == 0 {
                    rlim.rlim_cur = RLIM_INFINITY;
                    rlim.rlim_max = RLIM_INFINITY;

                    // 한도 상향 성공 시 2차 잠금 재시도
                    if set_rlimit(RLIMIT_MEMLOCK, &rlim) == 0 {
                        return mlock(ptr as *const c_void, len) == 0;
                    }
                }
            }
        }
        // 권한 부 족같은 이유로 최종 실패
        false
    }

    /// Unix 계열에서의 메모리 잠금 해제 구현
    ///
    /// `munlock` 시스템 콜을 사용합니다.
    #[cfg(unix)]
    pub unsafe fn unlock_memory(ptr: *mut u8, len: usize) {
        unsafe {
            munlock(ptr as *const c_void, len);
        }
    }

    /// Windows에서의 메모리 잠금 구현
    ///
    /// `VirtualLock` API를 사용하여 프로세스의 워킹 셋(Working Set)에 페이지를 고정합니다.
    /// 성공 시 `true` (0이 아님), 실패 시 `false` (0)를 반환합니다.
    #[cfg(windows)]
    pub unsafe fn lock_memory(ptr: *mut u8, len: usize) -> bool {
        VirtualLock(ptr as *const c_void, len) != 0
    }

    /// Windows에서의 메모리 잠금 해제 구현
    ///
    /// `VirtualUnlock` API를 사용합니다.
    #[cfg(windows)]
    pub unsafe fn unlock_memory(ptr: *mut u8, len: usize) {
        VirtualUnlock(ptr as *const c_void, len);
    }
}
