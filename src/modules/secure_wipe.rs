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

use std::panic;
use zeroize::Zeroize;

use crate::helper::slice_from_raw_mut;

/// `Java MemorySegment`의 주소와 길이를 받아 안전하게 소거합니다.
///
/// # Safety
/// 이 함수는 FFI 경계에서 호출되기 떄문에 패닉이 발생해도 JVM을 중단시키지 않도록
/// `catch_unwind`로 감싸져 있습니다. 다만, 여전히 `ptr`은 유효한 메모리 주소여야 합니다.
#[unsafe(no_mangle)]
pub extern "C" fn entanglement_secure_wipe(ptr: *mut u8, len: usize) {
    // Rust 내부 패닉이 JVM으로 전파되지 않도록 차단
    let result = panic::catch_unwind(|| {
        unsafe {
            if let Ok(data) = slice_from_raw_mut(ptr, len) {
                data.zeroize();
            }
        }
    });

    // 패닉 발생 시 로깅
    if result.is_err() {
        eprintln!("[EntLib-Native] 치명적 에러: 보안 삭제 중 패닉이 발생했습니다!");
    }
}
