use crate::core::{HkdfHash, sp800_56c_expand_counter_mode, sp800_56c_extract};
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use entlib_native_sha2::api::{SHA256, SHA512};

//
// 내부 트레이트 구현부 (Implementations for External Crates)
//

impl HkdfHash for SHA256 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;

    fn new() -> Self {
        SHA256::new()
    }
    fn update(&mut self, data: &[u8]) {
        self.update(data)
    }
    fn finalize(self) -> Vec<u8> {
        self.finalize()
    }
}

impl HkdfHash for SHA512 {
    const BLOCK_SIZE: usize = 128;
    const OUTPUT_SIZE: usize = 64;

    fn new() -> Self {
        SHA512::new()
    }
    fn update(&mut self, data: &[u8]) {
        self.update(data)
    }
    fn finalize(self) -> Vec<u8> {
        self.finalize()
    }
}

//
// Public APIs (SP 800-56C Rev. 2 / SP 800-108 Variants)
//

/// SP 800-56C Rev. 2 기반 KDF (SHA256) API
pub struct KdfSha256;

impl KdfSha256 {
    /// Step 1: Randomness Extraction
    /// Salt와 공유 비밀키(Z)를 받아 마스터 키(K_mc)를 추출합니다.
    pub fn extract(salt: Option<&[u8]>, z: &[u8]) -> SecureBuffer {
        sp800_56c_extract::<SHA256>(salt, z)
    }

    /// Step 2: Key Expansion (Counter Mode)
    /// 마스터 키(K_mc), 용도 식별자(Label), 상황 정보(Context)를 받아 원하는 길이의 키를 파생합니다.
    pub fn expand(
        k_mc: &[u8],
        label: &[u8],
        context: &[u8],
        len_bytes: usize,
    ) -> Result<SecureBuffer, &'static str> {
        sp800_56c_expand_counter_mode::<SHA256>(k_mc, label, context, len_bytes)
    }

    /// Extract와 Expand를 단일 호출로 수행합니다.
    pub fn oneshot(
        salt: Option<&[u8]>,
        z: &[u8],
        label: &[u8],
        context: &[u8],
        len_bytes: usize,
    ) -> Result<SecureBuffer, &'static str> {
        let k_mc = Self::extract(salt, z);
        Self::expand(&k_mc.inner, label, context, len_bytes)
    }
}

/// SP 800-56C Rev. 2 기반 KDF (SHA512) API
pub struct KdfSha512;

impl KdfSha512 {
    /// Step 1: Randomness Extraction
    pub fn extract(salt: Option<&[u8]>, z: &[u8]) -> SecureBuffer {
        sp800_56c_extract::<SHA512>(salt, z)
    }

    /// Step 2: Key Expansion (Counter Mode)
    pub fn expand(
        k_mc: &[u8],
        label: &[u8],
        context: &[u8],
        len_bytes: usize,
    ) -> Result<SecureBuffer, &'static str> {
        sp800_56c_expand_counter_mode::<SHA512>(k_mc, label, context, len_bytes)
    }

    /// Extract와 Expand를 단일 호출로 수행합니다.
    pub fn oneshot(
        salt: Option<&[u8]>,
        z: &[u8],
        label: &[u8],
        context: &[u8],
        len_bytes: usize,
    ) -> Result<SecureBuffer, &'static str> {
        let k_mc = Self::extract(salt, z);
        Self::expand(&k_mc.inner, label, context, len_bytes)
    }
}
