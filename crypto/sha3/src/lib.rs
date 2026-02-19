pub mod api;
mod keccak;

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

/// Keccak 스펀지 함수의 내부 상태 구조체(internal state structure)
pub(crate) struct KeccakState {
    pub(crate) state: [u64; 25],
    pub(crate) rate_bytes: usize,
    pub(crate) buffer: [u8; 200],
    pub(crate) buffer_len: usize,
    pub(crate) domain: u8,
}

impl Drop for KeccakState {
    fn drop(&mut self) {
        // 내부 상태 배열 및 버퍼 소거(zeroization of internal state and buffer)
        for i in 0..25 {
            unsafe {
                write_volatile(&mut self.state[i], 0);
            }
        }
        for i in 0..200 {
            unsafe {
                write_volatile(&mut self.buffer[i], 0);
            }
        }
        unsafe {
            write_volatile(&mut self.buffer_len, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}
