use crate::FFIStatus;
use core::ptr;
use core::slice;
use entlib_native_helper::secure_buffer::SecureBuffer;
use entlib_native_sha2::api::{SHA224, SHA256, SHA384, SHA512};

macro_rules! generate_sha2_ffi {
    ($struct_type:ty, $new_fn:ident, $update_fn:ident, $finalize_fn:ident, $free_fn:ident) => {
        /// 해시 컨텍스트 초기화 (initialize hash context)
        #[unsafe(no_mangle)]
        pub extern "C" fn $new_fn() -> *mut $struct_type {
            let instance = Box::new(<$struct_type>::new());
            Box::into_raw(instance)
        }

        /// 데이터 주입 및 상태 업데이트 (update hash state)
        ///
        /// # Safety
        /// - `ctx`는 `$new_fn`을 통해 할당된 유효한 포인터여야 합니다.
        /// - `data` 포인터는 최소 `len` 바이트 크기의 읽기 가능한 메모리를 가리켜야 합니다.
        /// - 동일한 컨텍스트에 대한 동시 접근 시 스레드-안전(thread-safe)을 보장하기 위해 호출 측에서 동기화해야 합니다.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $update_fn(
            ctx: *mut $struct_type,
            data: *const u8,
            len: usize,
        ) -> i32 {
            if ctx.is_null() {
                return FFIStatus::NullPointerError as i32;
            }
            if data.is_null() && len > 0 {
                return FFIStatus::NullPointerError as i32;
            }

            let slice = unsafe { slice::from_raw_parts(data, len) };
            let hasher = unsafe { &mut *ctx };

            hasher.update(slice);

            FFIStatus::Success as i32
        }

        /// 연산 완료 및 보안 버퍼 반환 (finalize and return secure buffer)
        ///
        /// 자바 영역으로 데이터를 복사하지 않고, 안전하게 소거되는 `SecureBuffer`의 포인터를 반환합니다.
        ///
        /// # Safety
        /// - `ctx`는 유효한 포인터여야 하며, 호출 후 소유권이 소비(consume)되어 내부 상태가 자동 소거됩니다.
        /// - 반환된 `SecureBuffer` 포인터는 자바 측에서 사용이 끝난 직후 반드시 `entlib_secure_buffer_free`를 통해 수동으로 해제되어야 합니다.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $finalize_fn(ctx: *mut $struct_type) -> *mut SecureBuffer {
            if ctx.is_null() {
                return ptr::null_mut();
            }

            let hasher = unsafe { Box::from_raw(ctx) };
            let digest = hasher.finalize(); // Vec<u8> 반환

            // 다이제스트를 SecureBuffer로 캡슐화하여 힙에 할당
            let secure_buffer = Box::new(SecureBuffer { inner: digest });
            Box::into_raw(secure_buffer)
        }

        /// 예외 발생 시 해시 컨텍스트 조기 폐기 (early free on exception)
        ///
        /// # Safety
        /// - `ctx`가 null이 아닐 경우 강제로 소유권을 가져와 메모리를 해제합니다.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $free_fn(ctx: *mut $struct_type) {
            if !ctx.is_null() {
                unsafe {
                    drop(Box::from_raw(ctx));
                }
            }
        }
    };
}

// SHA2 ffi 엔드포인트 자동 생성
generate_sha2_ffi!(
    SHA224,
    entlib_sha224_new,
    entlib_sha224_update,
    entlib_sha224_finalize,
    entlib_sha224_free
);
generate_sha2_ffi!(
    SHA256,
    entlib_sha256_new,
    entlib_sha256_update,
    entlib_sha256_finalize,
    entlib_sha256_free
);
generate_sha2_ffi!(
    SHA384,
    entlib_sha384_new,
    entlib_sha384_update,
    entlib_sha384_finalize,
    entlib_sha384_free
);
generate_sha2_ffi!(
    SHA512,
    entlib_sha512_new,
    entlib_sha512_update,
    entlib_sha512_finalize,
    entlib_sha512_free
);
