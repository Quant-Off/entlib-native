#![no_std]

extern crate alloc;

mod hkdf;

// 외부(Java FFI 등) 및 사용자가 접근할 수 있는 구조체와 상태(에러) Enum만 공개합니다.
pub use hkdf::{
    HKDFSHA3_224, HKDFSHA3_256, HKDFSHA3_384, HKDFSHA3_512, HKDFSHA224, HKDFSHA256, HKDFSHA384,
    HKDFSHA512, HKDFState,
};
