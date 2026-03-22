mod error;
mod length;
mod reader;
mod writer;

pub use error::DerError;
pub use reader::{DerReader, DerTlv};
pub use writer::DerWriter;

/// 최대 허용 중첩 깊이
/// 재귀 폭탄 방어
pub const MAX_DEPTH: u8 = 16;