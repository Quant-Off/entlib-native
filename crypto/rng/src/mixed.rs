//! 하드웨어 엔트로피 혼합 및 확장 모듈
//!
//! # Author
//! Q. T. Felix
//!
//! # Security
//! 프로세서 레벨의 진난수 생성기(trng) 출력값을 직접 사용하지 않고,
//! `chacha20` 스트림 암호(stream cipher)의 코어 블록 함수를 통해
//! 비선형적으로 혼합(mixing)합니다.
//! 내부 연산에 사용되는 모든 레지스터 및 상태 배열은 함수 종료 또는
//! 객체 소멸 시 스택에서 강제 소거(zeroize)됩니다.
//!
//! # Note
//! 이 기능은 곧 `chacha20` 모듈로 차별화됩니다.

use crate::anu_qrng::AnuQrngClient;
use crate::base_rng::{RngError, generate_hardware_random_bytes};
use core::ptr::{copy_nonoverlapping, write_volatile};
use core::sync::atomic::{Ordering, compiler_fence};
use entlib_native_core_secure::secure_buffer::SecureBuffer;

/// 상수 시간(constant-time) 연산을 보장하는 chacha20 쿼터 라운드(quarter round)
macro_rules! quarter_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(8);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(7);
    };
}

/// 엔트로피 소스(entropy source)를 결정하는 전략(strategy) 열거형
pub enum EntropyStrategy {
    /// 로컬 프로세서의 하드웨어 난수 생성기(`rdseed`, `rndr` 등)를 사용합니다.
    LocalHardware,
    /// ANU 양자 난수 API를 통해 진공 양자 요동(quantum vacuum fluctuations) 데이터를 가져옵니다.
    QuantumNetwork,
}

/// 혼합 난수 생성기(mixed rng) 구조체
///
/// 하드웨어 진난수를 시드(seed)로 사용하여 512-비트(bit) 상태를 초기화합니다.
pub struct MixedRng {
    state: [u32; 16],
}

impl MixedRng {
    /// 지정된 엔트로피 전략을 사용하여 새로운 혼합 난수 생성기를 인스턴스화합니다.
    pub fn new(strategy: EntropyStrategy) -> Result<Self, RngError> {
        // 전략 패턴(strategy pattern)에 따른 시드(seed) 추출 분기
        let (hw_key, hw_nonce) = match strategy {
            EntropyStrategy::LocalHardware => (
                generate_hardware_random_bytes(32)?,
                generate_hardware_random_bytes(12)?,
            ),
            EntropyStrategy::QuantumNetwork => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        RngError::NetworkFailure(format!("tokio 런타임 빌드 실패: {}", e))
                    })?;
                rt.block_on(async {
                    let key = AnuQrngClient::fetch_secure_bytes(32).await?;
                    let nonce = AnuQrngClient::fetch_secure_bytes(12).await?;
                    Ok::<(SecureBuffer, SecureBuffer), RngError>((key, nonce))
                })?
            }
        };

        let mut state = [0u32; 16];

        // chacha20 상수(constants) 배열 초기화
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        unsafe {
            let key_ptr = hw_key.inner.as_ptr() as *const u32;
            let nonce_ptr = hw_nonce.inner.as_ptr() as *const u32;

            for i in 0..8 {
                state[4 + i] = core::ptr::read_unaligned(key_ptr.add(i));
            }
            for i in 0..3 {
                state[13 + i] = core::ptr::read_unaligned(nonce_ptr.add(i));
            }
        }

        // 블록 카운터(block counter)
        state[12] = 0;

        // hw_key와 hw_nonce는 SecureBuffer의 Drop 트레이트 구현에 의해
        // 스코프를 벗어날 때 자동으로 데이터 소거(zeroize)가 수행됨

        Ok(Self { state })
    }

    /// 요청된 길이(len)만큼의 혼합 난수를 담은 보안 버퍼(secure buffer)를 반환합니다.
    pub fn generate(&mut self, len: usize) -> Result<SecureBuffer, RngError> {
        let mut buffer: Vec<u8> = Vec::with_capacity(len);
        let mut offset = 0;
        let mut block = [0u32; 16];

        unsafe {
            let ptr: *mut _ = buffer.as_mut_ptr();

            while offset < len {
                self.chacha_block(&mut block);

                let remain = len - offset;
                let copy_len = if remain < 64 { remain } else { 64 };

                copy_nonoverlapping(block.as_ptr() as *const u8, ptr.add(offset), copy_len);

                offset += copy_len;
                self.state[12] = self.state[12].wrapping_add(1);
            }

            buffer.set_len(len);

            // 임시 블록 스택 소거(zeroize)
            for word in block.iter_mut() {
                write_volatile(word, 0);
            }
            compiler_fence(Ordering::SeqCst);
        }

        Ok(SecureBuffer { inner: buffer })
    }

    /// 단일 chacha20 블록을 연산합니다.
    #[inline(always)]
    fn chacha_block(&self, out: &mut [u32; 16]) {
        let mut x = self.state;

        // 20 라운드(10 번의 이중 라운드)
        for _ in 0..10 {
            // 열(column) 라운드
            quarter_round!(x[0], x[4], x[8], x[12]);
            quarter_round!(x[1], x[5], x[9], x[13]);
            quarter_round!(x[2], x[6], x[10], x[14]);
            quarter_round!(x[3], x[7], x[11], x[15]);
            // 대각선(diagonal) 라운드
            quarter_round!(x[0], x[5], x[10], x[15]);
            quarter_round!(x[1], x[6], x[11], x[12]);
            quarter_round!(x[2], x[7], x[8], x[13]);
            quarter_round!(x[3], x[4], x[9], x[14]);
        }

        for i in 0..16 {
            out[i] = x[i].wrapping_add(self.state[i]);
        }
    }
}

impl Drop for MixedRng {
    fn drop(&mut self) {
        // 객체 소멸 시 상태(state) 배열 강제 소거
        for word in self.state.iter_mut() {
            unsafe {
                write_volatile(word, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
