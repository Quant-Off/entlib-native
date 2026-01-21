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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceError {
    NullPointer,
    ZeroLength,
    LengthOverflow,
}

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

pub unsafe fn bytes_from_raw_mut(ptr: *mut u8, len: usize) -> Result<Vec<u8>, SliceError> {
    unsafe { bytes_from_raw(ptr as *const u8, len) }
}

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