use crate::{Sha256State, Sha512State};

//
// SHA224 - start
//
pub struct SHA224(Sha256State);
impl SHA224 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(Sha256State::new(true))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

impl Default for SHA224 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA224 - end
//

//
// SHA256 - start
//
pub struct SHA256(Sha256State);
impl SHA256 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(Sha256State::new(false))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

impl Default for SHA256 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA256 - end
//

//
// SHA384 - start
//
pub struct SHA384(Sha512State);
impl SHA384 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(Sha512State::new(true))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

impl Default for SHA384 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA384 - end
//

//
// SHA512 - start
//
pub struct SHA512(Sha512State);
impl SHA512 {
    // 인스턴스 초기화
    pub fn new() -> Self {
        Self(Sha512State::new(false))
    }

    // 해시 대상 데이터 주입
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    // 해시 연산 완료 및 다이제스트 반환
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

impl Default for SHA512 {
    fn default() -> Self {
        Self::new()
    }
}
//
// SHA512 - end
//
