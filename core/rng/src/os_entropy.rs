use core::arch::asm;
use entlib_native_base::error::rng::RngError;
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha3::api::SHA3_256;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn extract_os_entropy(size: usize) -> Result<SecureBuffer, RngError> {
    let mut buffer = SecureBuffer::new_owned(size)?;
    let buf_slice = buffer.as_mut_slice();
    let mut read_bytes = 0;

    // SYS_getrandom = 318, flags = 0 (/dev/urandom 동작)
    while read_bytes < size {
        let ret: isize;
        unsafe {
            asm!(
            "syscall",
            in("rax") 318usize,
            in("rdi") buf_slice[read_bytes..].as_mut_ptr(),
            in("rsi") size - read_bytes,
            in("rdx") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rax") ret,
            );
        }
        if ret < 0 {
            let errno = -ret;
            if errno == 4 {
                // EINTR
                continue;
            }
            return Err(RngError::OsKernelError);
        }
        if ret == 0 {
            return Err(RngError::EntropySourceEof);
        }
        read_bytes += ret as usize;
    }

    Ok(buffer)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub fn extract_os_entropy(size: usize) -> Result<SecureBuffer, RngError> {
    let mut buffer = SecureBuffer::new_owned(size)?;
    let buf_slice = buffer.as_mut_slice();
    let mut read_bytes = 0;

    // SYS_getrandom = 278 (aarch64 Linux), flags = 0 (/dev/urandom 동작)
    while read_bytes < size {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                in("x8") 278usize,
                in("x0") buf_slice[read_bytes..].as_mut_ptr(),
                in("x1") size - read_bytes,
                in("x2") 0usize,
                lateout("x0") ret,
                options(nostack),
            );
        }
        if ret < 0 {
            if -ret == 4 {
                // EINTR
                continue;
            }
            return Err(RngError::OsKernelError);
        }
        if ret == 0 {
            return Err(RngError::EntropySourceEof);
        }
        read_bytes += ret as usize;
    }

    Ok(buffer)
}

#[cfg(target_os = "macos")]
pub fn extract_os_entropy(size: usize) -> Result<SecureBuffer, RngError> {
    if size > 256 {
        return Err(RngError::SizeLimitExceeded);
    }
    let mut buffer = SecureBuffer::new_owned(size)?;
    unsafe extern "C" {
        fn getentropy(buf: *mut u8, buflen: usize) -> i32;
    }
    let ret = unsafe { getentropy(buffer.as_mut_slice().as_mut_ptr(), size) };
    if ret != 0 {
        return Err(RngError::OsKernelError);
    }
    Ok(buffer)
}

#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub fn extract_hardware_entropy(size: usize) -> Result<SecureBuffer, RngError> {
    let mut buffer = SecureBuffer::new_owned(size)?;
    let buf_slice = buffer.as_mut_slice();

    if !size.is_multiple_of(8) {
        return Err(RngError::InvalidAlignment);
    }

    let qwords = size / 8;
    for i in 0..qwords {
        let mut seed: u64 = 0;
        let mut success: u8 = 0;

        let mut retries = 100;
        while retries > 0 {
            unsafe {
                asm!(
                "rdseed {0}",
                "setc {1}",
                out(reg) seed,
                out(reg_byte) success,
                );
            }

            if success == 1 {
                break;
            }

            // CPU 파이프라인 지연을 위한 pause
            unsafe { asm!("pause") };
            retries -= 1;
        }

        if success == 0 {
            return Err(RngError::HardwareEntropyExhausted);
        }

        buf_slice[i * 8..(i + 1) * 8].copy_from_slice(&seed.to_ne_bytes());
    }

    Ok(buffer)
}

#[cfg(target_arch = "aarch64")]
pub fn extract_hardware_entropy_arm(size: usize) -> Result<SecureBuffer, RngError> {
    let mut buffer = SecureBuffer::new_owned(size)?;
    let buf_slice = buffer.as_mut_slice();

    if !size.is_multiple_of(8) {
        return Err(RngError::InvalidAlignment);
    }

    let qwords = size / 8;
    for i in 0..qwords {
        let mut seed: u64 = 0;
        let mut success: u64; // ARM 상태 플래그 확인용

        // RNDRRS 레지스터에서 값을 읽음
        // 실패 시 Z 플래그(Zero)가 1로 설정
        unsafe {
            asm!(
            "mrs {0}, s3_3_c2_c4_1", // RNDRRS의 시스템 레지스터 인코딩
            "cset {1}, ne",          // Z 플래그가 0이면(ne) 성공(1)
            out(reg) seed,
            out(reg) success,
            );
        }

        if success == 0 {
            return Err(RngError::HardwareEntropyExhausted);
        }

        buf_slice[i * 8..(i + 1) * 8].copy_from_slice(&seed.to_ne_bytes());
    }

    Ok(buffer)
}

// Q. T. Felix TODO: x86_64, ARM64 베어메탈 std/no_std 환경 대응하는 엔트로피 소스 추출 기능

/// OS 시스템 콜이나 CPU 명령어에서 얻은 원시 엔트로피(Raw Entropy)는 즉시 암호 키로 사용되어서는
/// 안 됩니다. NIST SP 800-90C 지침에 따라 검증된 암호학적 해시 함수를 통해 컨디셔닝(Conditioning)
/// 과정을 거쳐야 합니다.
#[allow(unused)]
pub fn condition_entropy(raw_entropy: &SecureBuffer) -> Result<SecureBuffer, RngError> {
    if raw_entropy.len() < 32 {
        return Err(RngError::InsufficientEntropy);
    }

    let mut hasher = SHA3_256::new();
    hasher.update(raw_entropy.as_slice());
    hasher.finalize().map_err(|e| match e {
        entlib_native_base::error::hash::HashError::Buffer(buf_err) => RngError::Buffer(buf_err),
        _ => RngError::Buffer(
            entlib_native_base::error::secure_buffer::SecureBufferError::AllocationFailed,
        ),
    })
}
