#![allow(non_camel_case_types)]

use crate::KeccakState;

//
// SHA3-224 - start
//
pub struct SHA3_224(KeccakState);
impl SHA3_224 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(1152, 0x06))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize(28)
    }
}

impl Default for SHA3_224 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA3-224 - end
//

//
// SHA3-256 - start
//
pub struct SHA3_256(KeccakState);
impl SHA3_256 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(1088, 0x06))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize(32)
    }
}

impl Default for SHA3_256 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA3-256 - end
//

//
// SHA3-384 - start
//
pub struct SHA3_384(KeccakState);
impl SHA3_384 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(832, 0x06))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize(48)
    }
}

impl Default for SHA3_384 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA3-384 - end
//

//
// SHA3-512 - start
//
pub struct SHA3_512(KeccakState);
impl SHA3_512 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(576, 0x06))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize(64)
    }
}

impl Default for SHA3_512 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA3-512 - end
//

//
// SHAKE128 - start
//
pub struct SHAKE128(KeccakState);
impl SHAKE128 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(1344, 0x1f))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // XOF 연산 완료 및 지정된 길이의 다이제스트 반환
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        self.0.finalize(output_len)
    }
}

impl Default for SHAKE128 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHAKE128 - end
//

//
// SHAKE256 - start
//
pub struct SHAKE256(KeccakState);
impl SHAKE256 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(KeccakState::new(1088, 0x1f))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // XOF 연산 완료 및 지정된 길이의 다이제스트 반환
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        self.0.finalize(output_len)
    }
}

impl Default for SHAKE256 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHAKE256 - end
//
