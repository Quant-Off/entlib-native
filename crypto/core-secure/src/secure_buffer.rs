//! `secure_buffer.rs` 모듈은 네이티브 환경과 외부 인프라 간에 민감 데이터를 주고받거나 가공할 때,
//! 데이터의 생명주기 전반에 걸쳐 극도의 기밀성을 유지하도록 설계된 핵심 메모리 관리 모듈입니다.
//!
//! 가비지 컬렉터의 불확실한 수거 주기에 의존하여 데이터가 메모리에 장기간 방치되는 취약점을 해결하고,
//! Zero-Trust 원칙에 입각하여 외부 요인에 의한 메모리 유출 시도를 원천 차단하는 역할을 수행합니다.
//!
//! # Features
//! 이 모듈이 제공하는 구체적인 핵심 역할은 다음과 같습니다.
//! - **물리적 메모리 잠금 (Anti-Swapping)**
//!   - OS 레벨의 시스템 콜([mlock], [munlock])을 직접 호출하여 버퍼가 할당된 물리적 메모리 페이지를 강제로 잠급니다.
//! 시스템의 메모리가 부족해지더라도 암호화 키나 평문 데이터가 하드 디스크의 스왑(swap) 영역이나 페이지 파일로 밀려나
//! 영구적인 포렌식 공격의 대상이 되는 것을 방지합니다.
//! - **최적화 우회 및 강제 메모리 소거 (Zeroization)**
//!   - 데이터 사용이 끝나는 즉시 메모리의 모든 바이트를 0으로 덮어써 완전히 파기합니다. 이 과정에서 [write_volatile]과
//! 메모리 배리어([compiler_fence])를 사용하여, 불필요한 연산이라고 판단하여 소거 코드를 삭제해버리는 컴파일러의 데드 코드
//! 제거(DCE) 최적화와 CPU의 리오더링을 완벽히 무력화합니다.
//! - **타이밍 사이드 채널 공격 방어**
//!   - 민감한 버퍼의 내용을 비교할 때 조기 종료(early return)를 허용하지 않습니다. 두 버퍼의 내용이 같은지 검사할 때,
//! 데이터의 일치 여부나 틀린 바이트의 위치에 관계없이 항상 완벽하게 동일한 실행 시간이 소요되도록 강제하는
//! 상수-시간(Constant-Time) 비교 로직을 적용하여 공격자의 유추를 차단합니다.
//! - **우발적 로깅 유출 방지 (Anti-Logging)**
//!   - 시스템 크래시 덤프나 개발자의 디버그 출력 실수로 인해 메모리 안의 평문이 로그 파일에 그대로 기록되는 대형 보안 사고를
//! 막습니다. 메모리 출력 시도 시 실제 데이터 대신 `REDACTED ...`라는 더미 문자열만 기록되도록 내부 구조를 은폐합니다.
//! - **메모리 소유권에 따른 생명주기 통제**
//!   - FFI 환경에서의 유연하고 안전한 상호 작용을 위해 두 가지 패턴의 래퍼(wrapper)를 제공합니다.
//!     - **`SecureBuffer`**: 네이티브 환경에서 동적으로 할당된 후 외부로 불투명 포인터를 넘길 때 사용되며, 할당부터
//! 완전한 파기까지의 모든 생명주기를 네이티브가 전적으로 통제합니다. 즉각적인 메모리 해제 지시가 올 때까지 데이터를 안전하게
//! 보호합니다.
//!     - **`FFIExternalSecureBuffer`**: Off-Heap에서 선제적으로 할당되어 전달된 메모리 영역을 래핑할 때
//! 사용됩니다. 네이티브의 연산이 끝난 후 소유권 해제는 외부에 위임하되, 데이터 자체에 대한 즉각적인 파기는 네이티브가 확실하게
//! 보장하는 구조를 취합니다.
//!
//! # Usage
//! `secure_buffer.rs` 모듈은 고도의 보안이 요구되는 네이티브 환경과 Java 측 Off-Heap 메모리 간의 상호작용에 맞추어
//! 설계되었습니다. 주요 시나리오별 사용법은 다음과 같습니다.
//!
//! ## 네이티브 환경에서 새로운 민감 데이터 생성 (`SecureBuffer`)
//! 난수 생성기나 암호화 알고리즘을 통해 Rust 측에서 새로운 키, 해시값, 암호문 등을 생성하여 반환해야 할 때 사용합니다.
//!
//! ```rust
//! use entlib_native_core_secure::secure_buffer::SecureBuffer;
//!
//! pub fn generate_secret_key() -> *mut SecureBuffer {
//!     // 1. 민감 데이터 생성 (예를 들어, 하드웨어 진난수 등)
//!     let raw_key = vec![0x1A, 0x2B, 0x3C, 0x4D];
//!
//!     // 2. 보안 버퍼로 래핑 (이 순간 OS 레벨 메모리 잠금 적용)
//!     let secure_key = SecureBuffer::new(raw_key);
//!
//!     // 3. Java로 넘기기 위해 Box로 감싸 불투명 포인터 반환
//!     Box::into_raw(Box::new(secure_key))
//! }
//!
//! // Java 측 연산이 끝난 후 호출되는 해제 함수
//! #[no_mangle]
//! pub extern "C" fn entlib_secure_buffer_free(ptr: *mut SecureBuffer) {
//!     if !ptr.is_null() {
//!         unsafe {
//!             // Box::from_raw로 소유권을 가져오면 즉시 Drop이 실행되어
//!             // 강제 소거(Zeroize) 및 메모리 잠금 해제가 수행됨
//!             let _ = Box::from_raw(ptr);
//!         }
//!     }
//! }
//!
//! ```
//!
//! ## Java가 제공한 Off-Heap 메모리 사용 (`FFIExternalSecureBuffer`)
//! Java 측에서 선제적으로 메모리를 확보하여 민감한 평문이나 암호문을 전달했을 때, Rust에서 이를 안전하게 다루고 소거하기 위해
//! 사용합니다. 이 경우 일반적으로 Java 측에선 호출자 패턴을 사용합니다.
//!
//! ```rust
//! use entlib_native_core_secure::secure_buffer::FFIExternalSecureBuffer;
//!
//! #[no_mangle]
//! pub extern "C" fn process_sensitive_data(data_ptr: *mut u8, data_len: usize) {
//!     // Java가 전달한 원시 포인터를 FFI 래퍼로 캡슐화
//!     let mut ext_buffer = FFIExternalSecureBuffer {
//!         inner: data_ptr,
//!         len: data_len,
//!     };
//!
//!     // 데이터 가공 및 암호화 로직 수행
//!     let slice = unsafe { core::slice::from_raw_parts_mut(ext_buffer.inner, ext_buffer.len) };
//!     // ... (암호화 처리) ...
//!
//!     // ext_buffer가 스코프를 벗어나며 Drop이 호출됨.
//!     // 이때 포인터가 가리키는 실제 메모리 영역이 0으로 덮어씌워짐.
//!     // (메모리 해제 권한은 여전히 Java에 있음)
//! }
//!
//! ```
//!
//! ## 타이밍 공격을 방어하는 데이터 비교 (상수-시간 비교)
//! MAC(메시지 인증 코드)이나 해시값을 검증할 때, 실행 시간 차이를 이용한 공격을 막기 위해 사용합니다.
//!
//! ```rust
//! fn verify_mac(expected_ptr: *mut u8, expected_len: usize, actual_mac: SecureBuffer) -> bool {
//!     // 외부에서 전달된 기대 MAC 값
//!     let expected_mac = FFIExternalSecureBuffer {
//!         inner: expected_ptr,
//!         len: expected_len,
//!     };
//!
//!     // 두 버퍼의 타입이 다르더라도 길이를 맞춘 후 내부 slice를 이용해
//!     // 상수-시간(Constant-Time) 비교를 수행하도록 응용 가능
//!
//!     // 예시: FFIExternalSecureBuffer 간의 비교
//!     let is_valid = expected_mac.ct_eq(&expected_mac);
//!
//!     is_valid
//! }
//!
//! ```
//!
//! ## 명시적 조기 소거 및 안티-로깅 확인
//! 데이터의 수명을 최소화하고 우발적인 유출을 막는 방법입니다.
//!
//! ```rust
//! fn handle_highly_classified_data() {
//!     let secret = SecureBuffer::new(vec![1, 2, 3, 4, 5]);
//!
//!     // 1. 실수로 로그 출력을 시도하더라도 [REDACTED SECURE BUFFER: 5 bytes] 로 출력됨
//!     println!("Extracted Secret: {:?}", secret);
//!
//!     // 2. 사용이 끝난 즉시 강제 파기 (스코프 종료를 기다리지 않음)
//!     secret.wipe_and_drop();
//!
//!     // 이후부터는 secret 변수 접근 불가
//! }
//!
//! ```
//!
//! # Authors
//! Q. T. Felix

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use std::fmt::{Debug, Formatter};

use entlib_native_constant_time::constant_time::ConstantTimeOps;

#[cfg(unix)]
unsafe extern "C" {
    fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
}

/// 메모리 소거를 보장하는 보안 버퍼 구조체입니다.
///
/// 이 구조체는 Rust가 할당하고 소유하는 메모리를 캡슐화합니다.
/// 네이티브 코드상에서 연산의 '결과물'을 새로 생성할 때 주로 사용됩니다.
/// (예: 인/디코딩 결과, 암호문 생성 등)
///
/// # Features
/// 1. 메모리 잠금 (Memory Locking): `mlock`을 사용하여 메모리가 스왑(Swap) 영역으로
///    페이지 아웃되는 것을 방지합니다. 이는 디스크에 평문이 남는 것을 막습니다.
/// 2. 자동 소거 (Zeroization): 구조체가 스코프를 벗어나거나 명시적으로 해제될 때,
///    `volatile` 쓰기를 통해 메모리를 0으로 덮어씁니다.
/// 3. 상수 시간 비교 (Constant-Time Comparison): 타이밍 공격을 방지하기 위한
///    비교 함수를 제공합니다.
/// 4. 안티 로깅 (Anti-Logging): `Debug` 트레이트 구현 시 실제 데이터를 출력하지 않습니다.
pub struct SecureBuffer {
    pub inner: Vec<u8>,
}

impl SecureBuffer {
    /// 새로운 `SecureBuffer`를 할당하고 즉시 OS 레벨에서 메모리를 잠급니다.
    ///
    /// 주어진 `data` 벡터의 소유권을 가져오며, 해당 메모리 영역에 대해 `mlock`을 호출하여
    /// 디스크 스왑으로 인한 평문 유출을 방지합니다.
    ///
    /// # Arguments
    /// * `data` - 보호할 데이터를 담은 바이트 벡터
    ///
    /// # Safety
    /// 내부적으로 `mlock` 시스템 콜을 사용합니다. `data` 벡터가 유효한 메모리를 점유하고
    /// 있으므로 안전하지만, 시스템 리소스 제한(RLIMIT_MEMLOCK)에 따라 실패할 수도 있습니다.
    /// 현재 구현은 실패 시 패닉하지 않고 진행합니다(Best-effort).
    pub fn new(data: Vec<u8>) -> Self {
        #[cfg(unix)]
        unsafe {
            // 외부 의존성(libc 등) 없이 직접 시스템 콜 호출
            // Safety: data.as_ptr()은 유효한 힙 메모리를 가리키며, data.len()은 그 길이를 정확히 나타냄
            mlock(data.as_ptr() as *const core::ffi::c_void, data.len());
        }
        Self { inner: data }
    }

    /// 상수 시간(Constant-Time)으로 두 버퍼의 내용을 비교합니다.
    ///
    /// 두 버퍼의 내용이 같은지 검사하며, 비교에 걸리는 시간이 데이터의 내용에 의존하지 않도록
    /// 하여 타이밍 공격(Timing Attack)을 방지합니다.
    ///
    /// # Returns
    /// 두 버퍼의 내용이 완전히 동일하면 `true`, 그렇지 않으면 `false`를 반환합니다.
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.inner.len() != other.inner.len() {
            return false;
        }

        // ConstantTimeOps를 활용한 상수-시간 검사 루프
        let mut is_equal: u8 = !0; // 0xFF (ct true)
        for (a, b) in self.inner.iter().zip(other.inner.iter()) {
            is_equal &= a.ct_eq(*b);
        }

        is_equal == !0
    }

    /// 스코프 종료를 기다리지 않고 즉각적으로 메모리를 소거하고 해제합니다.
    ///
    /// 이 메소드를 호출하면 `Drop` 트레이트가 즉시 실행되어 메모리 소거 및 잠금 해제가 수행됩니다.
    pub fn wipe_and_drop(self) {
        // self가 스코프를 벗어나면서 drop() 메소드가 즉시 실행
        drop(self);
    }
}

// 안티-로깅 방어 (Crash Dump, Println 등에서 데이터 노출 방지)
impl Debug for SecureBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED SECURE BUFFER: {} bytes]", self.inner.len())
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for byte in self.inner.iter_mut() {
            // volatile write -> 컴파일러 최적화(DCE) 방지하여 실제 메모리에 쓰기 강제
            unsafe {
                write_volatile(byte, 0);
            }
        }
        // 메모리 배리어로 소거 순서 보장 (컴파일러 및 CPU 리오더링 방지)
        compiler_fence(Ordering::SeqCst);

        // 소거가 완료된 후 메모리 잠금 해제
        #[cfg(unix)]
        unsafe {
            munlock(
                self.inner.as_ptr() as *const core::ffi::c_void,
                self.inner.len(),
            );
        }
    }
}

/// 외부(FFI)에서 할당된 메모리를 래핑하여 보안 기능을 제공하는 구조체입니다.
///
/// 주로 Java/Kotlin 측에서 Off-Heap 메모리에 할당한 민감 데이터를
/// Rust 쪽에서 안전하게 다루거나 소거할 때 사용됩니다.
///
/// # Secure Warning
/// 이 구조체는 `Drop` 시점에 `inner` 포인터가 가리키는 메모리를 0으로 소거(Zeroize)합니다.
/// 따라서 Java 측에서 해당 메모리를 계속 사용해야 한다면 이 구조체로 래핑해서는 안 되거나,
/// 수명 관리에 각별한 주의가 필요합니다.
#[repr(C)]
pub struct FFIExternalSecureBuffer {
    /// 외부 메모리의 시작 주소를 가리키는 포인터
    pub inner: *mut u8,
    /// 버퍼의 길이 (바이트 단위)
    pub len: usize,
}

impl FFIExternalSecureBuffer {
    /// FFI 버퍼 간의 상수 시간(Constant-Time) 비교를 수행합니다.
    ///
    /// # Safety
    /// `self.inner`와 `other.inner`가 유효한 메모리를 가리키고 있어야 하며,
    /// `self.len`과 `other.len`이 해당 메모리 영역의 올바른 크기여야 합니다.
    /// 유효하지 않은 포인터 접근 시 정의되지 않은 동작(UB)이 발생할 수 있습니다.
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        // 포인터 자체가 null인 경우 처리
        if self.inner.is_null() || other.inner.is_null() {
            return self.inner == other.inner;
        }

        let mut is_equal: u8 = !0;
        unsafe {
            // Safety: 호출자가 포인터와 길이의 유효성을 보장해야 함
            let self_slice = core::slice::from_raw_parts(self.inner, self.len);
            let other_slice = core::slice::from_raw_parts(other.inner, other.len);

            for (a, b) in self_slice.iter().zip(other_slice.iter()) {
                is_equal &= a.ct_eq(*b);
            }
        }

        is_equal == !0
    }
}

// FFI 영역 버퍼의 안티-로깅 방어
impl Debug for FFIExternalSecureBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED SECURE FFI BUFFER: {} bytes]", self.len) // Q. T. Felix NOTE: 더 좋은 방법이 있다면 그거 써도 됌
    }
}

impl Drop for FFIExternalSecureBuffer {
    fn drop(&mut self) {
        if self.inner.is_null() || self.len == 0 {
            return;
        }
        unsafe {
            // Safety: FFIExternalSecureBuffer가 생성될 때 항상 유효한 포인터와 길이를 받았다고 가정함
            // Drop 시점에 해당 메모리 영역을 0으로 덮어씀
            let slice = core::slice::from_raw_parts_mut(self.inner, self.len);
            for byte in slice.iter_mut() {
                write_volatile(byte, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
