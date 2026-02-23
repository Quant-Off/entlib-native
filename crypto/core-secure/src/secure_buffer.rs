use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

/// 메모리 소거를 보장하는 보안 버퍼 구조체입니다.
///
/// 이 구조체는 쉽게 말해 Rust가 할당하고 소유하는 메모리입니다.
/// 이 네이티브 코드상에서 연산의 '결과물'을 새로 생성할 때 사용됩니다.
/// `Base64` 디코딩 결과, 암호화된 사이퍼텍스트 생성 등의 상황을 예로
/// 들 수 있습니다.
///
/// 민감한 데이터를 사용한 연산 후 그 결과를 Java Heap으로 전달하는 경우,
/// 가비지 컬렉터의 생명주기에 종속되어 위험에 다시 노출되는 딜레마를 가지게
/// 됩니다. 이 문제를 해결하기 위해 단순히 `byte[]`와 같은 Java 데이터로
/// 직렬화(serialize)하지 않고, 이 구조체에 저장합니다.
///
/// Java 측으로는 오직 해당 메모리의 원시 포인만이 전달되기 떄문에 안전한
/// 데이터 관리가 가능합니다.
pub struct SecureBuffer {
    pub inner: Vec<u8>,
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for byte in self.inner.iter_mut() {
            // volatile write -> 컴파일러 dce 최적화 방지함
            unsafe {
                write_volatile(byte, 0);
            }
        }
        // 메모리 배리어로 소거 순서 보장
        compiler_fence(Ordering::SeqCst);
    }
}

/// 메모리 소거를 보장하며, Java 측에서 사용되는 보안 버퍼 구조체입니다.
///
/// 이 구조체는 Java 측에서 민감 데이터를 이미 Off-Heap 영역에 할당하여
/// 들고 있을 때 사용됩니다.
///
/// 민감한 데이터를 사용한 연산 후 그 결과를 Java Heap으로 전달하는 경우,
/// 가비지 컬렉터의 생명주기에 종속되어 위험에 다시 노출되는 딜레마를 가지게
/// 됩니다. 이 문제를 해결하기 위해 단순히 `byte[]`와 같은 Java 데이터로
/// 직렬화(serialize)하지 않고, 이 구조체에 저장합니다.
#[repr(C)]
pub struct FFIExternalSecureBuffer {
    pub inner: *mut u8,
    pub len: usize,
}

impl Drop for FFIExternalSecureBuffer {
    fn drop(&mut self) {
        if self.inner.is_null() || self.len == 0 {
            return;
        }
        unsafe {
            let slice = core::slice::from_raw_parts_mut(self.inner, self.len);
            for byte in slice.iter_mut() {
                write_volatile(byte, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
