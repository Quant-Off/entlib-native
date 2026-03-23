//! IO 오류 타입 모듈입니다.

/// 파일 I/O 중 발생하는 오류 열거형입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// 파일 읽기 실패
    ReadFailed,
    /// 파일 쓰기 실패
    WriteFailed,
    /// 파일 크기가 허용 한도를 초과
    FileTooLarge,
    /// 파일을 찾을 수 없음
    FileNotFound,
    /// 권한 부족
    PermissionDenied,
    /// 유효하지 않은 경로 (빈 경로, null 바이트 등)
    InvalidPath,
    /// 원자적 파일 교체(rename) 실패
    AtomicRenameFailed,
    /// SecureBuffer 할당 실패
    AllocationError,
}
