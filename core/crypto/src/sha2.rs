use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

/// SHA-256 및 SHA-224를 위한 32비트 내부 상태 구조체(internal state structure)
pub struct Sha256State {
    pub state: [u32; 8],
    pub buffer: [u8; 64],
    pub buffer_len: usize,
    pub total_len: u64,
    pub is_224: bool,
}

/// SHA-512 및 SHA-384를 위한 64비트 내부 상태 구조체(internal state structure)
pub struct Sha512State {
    pub state: [u64; 8],
    pub buffer: [u8; 128],
    pub buffer_len: usize,
    pub total_len: u128,
    pub is_384: bool,
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
                for i in 0..$buf_len {
                    unsafe {
                        write_volatile(&mut self.buffer[i], 0);
                    }
                }
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
