/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use std::slice;

/// 슬라이스 생성 중 발생할 수 있는 오류를 정의합니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceError {
    /// 포인터가 null인 경우
    NullPointer,
    /// 길이가 0인 경우
    ZeroLength,
    /// 길이가 너무 커서 오버플로우가 발생하는 경우
    LengthOverflow,
}

/// 원시 포인터와 길이를 사용하여 바이트 벡터를 생성합니다.
///
/// # Arguments
///
/// * `ptr` - 데이터의 시작을 가리키는 원시 포인터
/// * `len` - 데이터의 길이 (바이트 단위)
///
/// # Returns
///
/// * `Result<Vec<u8>, SliceError>` - 성공 시 바이트 벡터, 실패 시 오류
///
/// # Safety
///
/// 이 함수는 unsafe 블록 내에서 호출되어야 하며, 제공된 포인터가 유효하고
/// `len`만큼의 메모리에 접근 가능함을 보장해야 합니다.
pub unsafe fn bytes_from_raw(ptr: *const u8, len: usize) -> Result<Vec<u8>, SliceError> {
    if ptr.is_null() {
        return Err(SliceError::NullPointer);
    }

    if len == 0 {
        return Err(SliceError::ZeroLength);
    }

    if len > isize::MAX as usize {
        return Err(SliceError::LengthOverflow);
    }

    Ok(unsafe { slice::from_raw_parts(ptr, len) }.to_vec())
}

/// 변경 가능한 원시 포인터와 길이를 사용하여 바이트 벡터를 생성합니다.
///
/// # Arguments
///
/// * `ptr` - 데이터의 시작을 가리키는 변경 가능한 원시 포인터
/// * `len` - 데이터의 길이 (바이트 단위)
///
/// # Returns
///
/// * `Result<Vec<u8>, SliceError>` - 성공 시 바이트 벡터, 실패 시 오류
///
/// # Safety
///
/// 이 함수는 unsafe 블록 내에서 호출되어야 하며, 제공된 포인터가 유효하고
/// `len`만큼의 메모리에 접근 가능함을 보장해야 합니다.
pub unsafe fn bytes_from_raw_mut(ptr: *mut u8, len: usize) -> Result<Vec<u8>, SliceError> {
    unsafe { bytes_from_raw(ptr as *const u8, len) }
}

/// 원시 포인터에서 고정 크기 배열을 생성합니다.
///
/// # Arguments
///
/// * `ptr` - 데이터의 시작을 가리키는 원시 포인터
///
/// # Returns
///
/// * `Result<[u8; N], SliceError>` - 성공 시 고정 크기 배열, 실패 시 오류
///
/// # Safety
///
/// 이 함수는 unsafe 블록 내에서 호출되어야 하며, 제공된 포인터가 유효하고
/// `N`만큼의 메모리에 접근 가능함을 보장해야 합니다.
pub unsafe fn array_from_raw<const N: usize>(ptr: *const u8) -> Result<[u8; N], SliceError> {
    if ptr.is_null() {
        return Err(SliceError::NullPointer);
    }

    if N > isize::MAX as usize {
        return Err(SliceError::LengthOverflow);
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(unsafe { slice::from_raw_parts(ptr, N) });
    Ok(arr)
}

/// 변경 가능한 원시 포인터와 길이를 사용하여 변경 가능한 슬라이스를 생성합니다.
///
/// # Arguments
///
/// * `ptr` - 데이터의 시작을 가리키는 변경 가능한 원시 포인터
/// * `len` - 데이터의 길이 (바이트 단위)
///
/// # Returns
///
/// * `Result<&'a mut [u8], SliceError>` - 성공 시 변경 가능한 슬라이스, 실패 시 오류
///
/// # Safety
///
/// 이 함수는 unsafe 블록 내에서 호출되어야 하며, 제공된 포인터가 유효하고
/// `len`만큼의 메모리에 접근 가능함을 보장해야 합니다.
pub unsafe fn slice_from_raw_mut<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], SliceError> {
    if ptr.is_null() {
        return Err(SliceError::NullPointer);
    }

    if len == 0 {
        return Err(SliceError::ZeroLength);
    }

    if len > isize::MAX as usize {
        return Err(SliceError::LengthOverflow);
    }

    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}