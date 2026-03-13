use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
pub struct EntLibResult {
    type_id: i8,
    status: i8,
    data: *mut c_void,
}

impl EntLibResult {
    pub fn new(type_id: i8, status: i8) -> Self {
        Self {
            type_id,
            status,
            data: null_mut(),
        }
    }

    /// 구조체 기본 값으로 크레이트 식별자와 상태 코드를 반환하려고 할 때,
    /// 추가적인 인자를 반환할 수 있도록 하는 함수입니다.
    pub fn add_additional<T>(mut self, value: T) -> Self {
        // 데이터를 힙에 고정(Box)하고 포인터로 변환하여 소유권을 수동 관리로 전환
        self.data = Box::into_raw(Box::new(value)) as *mut c_void;
        self
    }
}
