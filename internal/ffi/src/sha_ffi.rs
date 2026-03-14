use crate::FFIStandard;
use entlib_native_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use entlib_native_result::EntLibResult;
use entlib_native_sha2::api::*;
use entlib_native_sha3::api::*;
use std::ptr::write_volatile;
use std::sync::atomic::{Ordering, compiler_fence};

const TYPE_ID_SHA2: i8 = 3;
const TYPE_ID_SHA3: i8 = 4;

macro_rules! impl_ffi_hash_func {
    (
        $fn_name:ident,    // 생성할 FFI 함수명
        $hasher_type:ty,   // 해시 엔진 타입
        $digest_size:expr, // 다이제스트 출력 크기 (바이트 단위)
        $type_id:expr      // EntLibResult에 사용할 크레이트 식별자
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            input: *const FFIStandard,
            output: *mut FFIStandard,
        ) -> EntLibResult {
            // 포인터 유효성 검증
            if input.is_null() || output.is_null() {
                return EntLibResult::new($type_id, -1);
            }

            // FFIStandard -> ManuallyDrop<SecureBuffer> 변환
            let in_buffer = match unsafe { (*input).into_domain_buffer() } {
                Ok(buf) => buf,
                Err(_) => return EntLibResult::new($type_id, -2),
            };
            let out_struct = unsafe { &mut *output };

            // 출력 버퍼 용량 검증 (공개 정보이므로 분기 허용)
            let required_capacity = $digest_size;
            if out_struct.len < required_capacity {
                return EntLibResult::new($type_id, -3);
            }

            // 해시 엔진 인스턴스화 및 연산 수행
            let mut hasher = <$hasher_type>::new();
            hasher.update(in_buffer.as_slice());
            match hasher.finalize() {
                Ok(result_buf) => {
                    let result = result_buf.as_slice();
                    unsafe {
                        let out_len = out_struct.len;

                        // 상수-시간 FFI 패딩 복사
                        for i in 0..out_len {
                            // i < required_capacity 반별 (i >= required_capacity 의 NOT)
                            let is_valid = i.ct_is_ge(&required_capacity).choice_not();

                            // out-of-bounds 접근 방지를 위한 안전한 인덱스 선택
                            let safe_idx = usize::ct_select(&0, &i, is_valid);
                            let valid_byte = result[safe_idx];

                            // 범위를 벗어난 공간은 GC 데이터 유출 막기 위해 상수-시간 0x00 처리
                            let byte_to_write = u8::ct_select(&0x00, &valid_byte, is_valid);
                            write_volatile(out_struct.ptr.add(i), byte_to_write);
                        }
                        compiler_fence(Ordering::SeqCst);
                    }
                    EntLibResult::new($type_id, 0).add_additional(required_capacity as isize)
                }
                Err(_) => EntLibResult::new($type_id, -4),
            }
        }
    };
}

/// 통합 제어 아키텍처(UCA) JO 패턴에 기반하여,
/// 불완전한 마지막 바이트(last_byte)와 유효 비트 수(valid_bits)를 처리하는
/// 고정 길이 다이제스트 해시 엔진용 상수-시간 FFI 함수 생성 매크로입니다.
macro_rules! impl_ffi_hash_bits_func {
    (
        $fn_name:ident,    // 생성할 FFI 함수명
        $hasher_type:ty,   // 해시 엔진 타입
        $digest_size:expr, // 다이제스트 출력 크기 (바이트 단위)
        $type_id:expr      // EntLibResult에 사용할 크레이트 식별자
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            input: *const FFIStandard,
            output: *mut FFIStandard,
            last_byte: u8, // Q. T. Felix TODO: https://github.com/Quant-Off/entlib-native/pull/9#issuecomment-4059961999
            valid_bits: usize,
        ) -> EntLibResult {
            // 포인터 유효성 검증
            if input.is_null() || output.is_null() {
                return EntLibResult::new($type_id, -1);
            }

            // 입력 비트 유효성 검증 (0~7 범위를 벗어난 악의적 입력 차단)
            if valid_bits > 7 {
                return EntLibResult::new($type_id, -5);
            }

            // FFIStandard -> ManuallyDrop<SecureBuffer> 변환
            let in_buffer = match unsafe { (*input).into_domain_buffer() } {
                Ok(buf) => buf,
                Err(_) => return EntLibResult::new($type_id, -2),
            };
            let out_struct = unsafe { &mut *output };

            // 출력 버퍼 용량 검증 (고정 크기 다이제스트 기준)
            let required_capacity = $digest_size;
            if out_struct.len < required_capacity {
                return EntLibResult::new($type_id, -3);
            }

            // 해시 엔진 인스턴스화 및 데이터 업데이트
            let mut hasher = <$hasher_type>::new();
            hasher.update(in_buffer.as_slice());
            match hasher.finalize_bits(last_byte, valid_bits) {
                Ok(result_buf) => {
                    let result = result_buf.as_slice();
                    unsafe {
                        let out_len = out_struct.len;

                        // 상수-시간 FFI 패딩 복사
                        // 다이제스트 크기를 초과하는 버퍼 영역은 물리적으로 0x00 완전 소거
                        for i in 0..out_len {
                            let is_valid = i.ct_is_ge(&required_capacity).choice_not();

                            // Out-of-bounds 방지를 위해 인덱스를 상수-시간으로 0으로 폴백(Fallback)
                            let safe_idx = usize::ct_select(&0, &i, is_valid);
                            let valid_byte = result[safe_idx];

                            // is_valid가 참이면 valid_byte, 그렇지 않으면 0x00
                            let byte_to_write = u8::ct_select(&0x00, &valid_byte, is_valid);

                            write_volatile(out_struct.ptr.add(i), byte_to_write);
                        }

                        // JNI 경계 이탈 전 완벽한 메모리 가시성 보장
                        compiler_fence(Ordering::SeqCst);
                    }
                    EntLibResult::new($type_id, 0).add_additional(required_capacity as isize)
                }
                Err(_) => EntLibResult::new($type_id, -4),
            }
        }
    };
}

/// 바이트가 정확히 맞아떨어지는 일반적인 XOF 연산을 위한 FFI 함수 생성 매크로입니다.
macro_rules! impl_ffi_xof_func {
    (
        $fn_name:ident,  // 생성할 FFI 함수명
        $hasher_type:ty, // 해시 엔진 타입
        $type_id:expr    // EntLibResult에 사용할 크레이트 식별자
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            input: *const FFIStandard,
            output: *mut FFIStandard,
        ) -> EntLibResult {
            if input.is_null() || output.is_null() {
                return EntLibResult::new($type_id, -1);
            }

            let in_buffer = match unsafe { (*input).into_domain_buffer() } {
                Ok(buf) => buf,
                Err(_) => return EntLibResult::new($type_id, -2),
            };
            let out_struct = unsafe { &mut *output };

            let requested_out_len = out_struct.len;

            // 비정상적으로 거대한 메모리 할당 요청 차단
            if requested_out_len == 0 || requested_out_len > 16_777_216 {
                return EntLibResult::new($type_id, -3);
            }

            let mut hasher = <$hasher_type>::new();
            hasher.update(in_buffer.as_slice());

            match hasher.finalize(requested_out_len) {
                Ok(result_buf) => {
                    let result = result_buf.as_slice();
                    unsafe {
                        // XOF는 요청한 길이(requested_out_len)만큼 정확히 버퍼를 생성
                        // 고정 길이 SHA-2처럼 초과분에 대한 상수-시간 패딩(0x00)이 필요없음
                        for i in 0..requested_out_len {
                            write_volatile(out_struct.ptr.add(i), result[i]);
                        }

                        // JNI 경계를 넘기 전 메모리 가시성(Visibility) 보장
                        compiler_fence(Ordering::SeqCst);
                    }
                    EntLibResult::new($type_id, 0).add_additional(requested_out_len as isize)
                }
                Err(_) => EntLibResult::new($type_id, -4),
            }
        }
    };
}

/// 불완전한 마지막 바이트(last_byte)와 유효 비트 수(valid_bits) 처리가 필요한
/// 고급 XOF(cSHAKE, KMAC 등 파생 알고리즘) FFI 함수 생성 매크로입니다.
macro_rules! impl_ffi_xof_bits_func {
    (
        $fn_name:ident,
        $hasher_type:ty,
        $type_id:expr
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            input: *const FFIStandard,
            output: *mut FFIStandard,
            last_byte: u8,
            valid_bits: usize,
        ) -> EntLibResult {
            if input.is_null() || output.is_null() {
                return EntLibResult::new($type_id, -1);
            }

            // 비트 수 유효성 검증 (0~7 범위 이탈 시 에러 반환)
            if valid_bits > 7 {
                return EntLibResult::new($type_id, -5);
            }

            let in_buffer = match unsafe { (*input).into_domain_buffer() } {
                Ok(buf) => buf,
                Err(_) => return EntLibResult::new($type_id, -2),
            };
            let out_struct = unsafe { &mut *output };

            let requested_out_len = out_struct.len;

            if requested_out_len == 0 || requested_out_len > 16_777_216 {
                return EntLibResult::new($type_id, -3);
            }

            let mut hasher = <$hasher_type>::new();
            hasher.update(in_buffer.as_slice());
            match hasher.finalize_bits(requested_out_len, last_byte, valid_bits) {
                Ok(result_buf) => {
                    let result = result_buf.as_slice();
                    unsafe {
                        for i in 0..requested_out_len {
                            write_volatile(out_struct.ptr.add(i), result[i]);
                        }
                        compiler_fence(Ordering::SeqCst);
                    }
                    EntLibResult::new($type_id, 0).add_additional(requested_out_len as isize)
                }
                Err(_) => EntLibResult::new($type_id, -4),
            }
        }
    };
}

// SHA2 ffi 엔드포인트 생성
impl_ffi_hash_func!(ffi_sha2_224, SHA224, 28, TYPE_ID_SHA2);
impl_ffi_hash_func!(ffi_sha2_256, SHA256, 32, TYPE_ID_SHA2);
impl_ffi_hash_func!(ffi_sha2_384, SHA384, 48, TYPE_ID_SHA2);
impl_ffi_hash_func!(ffi_sha2_512, SHA512, 64, TYPE_ID_SHA2);

// SHA3 ffi 엔드포인트 생성
impl_ffi_hash_func!(ffi_sha3_224, SHA3_224, 28, TYPE_ID_SHA3);
impl_ffi_hash_func!(ffi_sha3_256, SHA3_256, 32, TYPE_ID_SHA3);
impl_ffi_hash_func!(ffi_sha3_384, SHA3_384, 48, TYPE_ID_SHA3);
impl_ffi_hash_func!(ffi_sha3_512, SHA3_512, 64, TYPE_ID_SHA3);

// SHA3 계열 부분 바이트 FFI 인터페이스 생성
impl_ffi_hash_bits_func!(ffi_sha3_224_bits, SHA3_256, 28, TYPE_ID_SHA3);
impl_ffi_hash_bits_func!(ffi_sha3_256_bits, SHA3_512, 32, TYPE_ID_SHA3);
impl_ffi_hash_bits_func!(ffi_sha3_384_bits, SHA3_256, 48, TYPE_ID_SHA3);
impl_ffi_hash_bits_func!(ffi_sha3_512_bits, SHA3_512, 64, TYPE_ID_SHA3);

// 일반적인 바이트 정렬 SHAKE 인터페이스 생성
impl_ffi_xof_func!(ffi_shake128, SHAKE128, TYPE_ID_SHA3);
impl_ffi_xof_func!(ffi_shake256, SHAKE256, TYPE_ID_SHA3);

// 비트 단위 패딩이 필요한 경우를 위한 인터페이스 생성
impl_ffi_xof_bits_func!(ffi_shake128_bits, SHAKE128, TYPE_ID_SHA3);
impl_ffi_xof_bits_func!(ffi_shake256_bits, SHAKE256, TYPE_ID_SHA3);
