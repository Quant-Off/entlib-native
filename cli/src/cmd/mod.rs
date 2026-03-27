use entlib_native_secure_buffer::SecureBuffer;

pub mod argon2id;
pub mod base64;
pub mod blake;
pub mod hex;
pub mod mldsa;
pub mod mlkem;
pub mod pkcs8;
pub mod sha2;
pub mod sha3;

pub(crate) fn hex_encode(digest: SecureBuffer) -> SecureBuffer {
    match entlib_native_hex::encode(&digest) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hex 인코딩 오류: {e}");
            std::process::exit(1);
        }
    }
}
