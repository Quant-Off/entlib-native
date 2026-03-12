pub mod api;
mod sha2_256;
mod sha2_512;

use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_secure_buffer::SecureBuffer;

/// SHA-256 및 SHA-224를 위한 32비트 내부 상태 구조체(internal state structure)
pub(crate) struct Sha256State {
    pub(crate) state: [u32; 8],
    pub(crate) buffer: SecureBuffer,
    pub(crate) buffer_len: usize,
    pub(crate) total_len: u64,
    pub(crate) is_224: bool,
}

/// SHA-512 및 SHA-384를 위한 64비트 내부 상태 구조체(internal state structure)
pub(crate) struct Sha512State {
    pub(crate) state: [u64; 8],
    pub(crate) buffer: SecureBuffer,
    pub(crate) buffer_len: usize,
    pub(crate) total_len: u128,
    pub(crate) is_384: bool,
}

macro_rules! impl_zeroize_drop {
    ($type:ty, $state_type:ty, $state_len:expr, $buf_len:expr) => {
        impl Drop for $type {
            fn drop(&mut self) {
                // 내부 상태 배열 및 버퍼 소거(zeroization of internal state and buffer)
                for i in 0..$state_len {
                    unsafe {
                        write_volatile(&mut self.state[i], 0);
                    }
                }
                // Q. T. Felix NOTE: 이 Drop 트레이트가 호출되는 시점에 SecureBuffer 구조체의 Drop 트레이트도 호출되지 않나?
                //                   만약 그렇지 않다면, Drop 트레이트를 이 곳에서 수동으로 직접 호출해주어야 함.
                unsafe {
                    write_volatile(&mut self.buffer_len, 0);
                    write_volatile(&mut self.total_len, 0);
                }
                compiler_fence(Ordering::SeqCst);
            }
        }
    };
}

impl_zeroize_drop!(Sha256State, u32, 8, 64);
impl_zeroize_drop!(Sha512State, u64, 8, 128);
