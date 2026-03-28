use super::hex_encode;
use crate::input;
use clap::Subcommand;
use entlib_native_argon2id::Argon2id;
use entlib_native_secure_buffer::SecureBuffer;

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// Argon2id 해시 생성
    Hash {
        /// 비밀번호 파일 (생략 시 stdin)
        #[arg(long)]
        in_file: Option<String>,
        /// 솔트 (hex 문자열)
        #[arg(long, group = "salt_src")]
        salt: Option<String>,
        /// 솔트 파일 (raw 바이너리)
        #[arg(long, group = "salt_src")]
        salt_file: Option<String>,
        /// 시간 비용 (기본: 2)
        #[arg(long, default_value_t = 2)]
        time_cost: u32,
        /// 메모리 비용 KiB (기본: 19456)
        #[arg(long, default_value_t = 19456)]
        memory_cost: u32,
        /// 병렬성 (기본: 1)
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
        /// 출력 태그 길이 바이트 (기본: 32)
        #[arg(long, default_value_t = 32)]
        tag_length: u32,
        /// 출력 파일 (생략 시 stdout)
        #[arg(long)]
        out_file: Option<String>,
        /// raw 바이너리 출력 (기본: hex)
        #[arg(long)]
        raw: bool,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Hash {
            in_file,
            salt,
            salt_file,
            time_cost,
            memory_cost,
            parallelism,
            tag_length,
            out_file,
            raw,
        } => run_hash(
            in_file,
            salt,
            salt_file,
            time_cost,
            memory_cost,
            parallelism,
            tag_length,
            out_file,
            raw,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_hash(
    in_file: Option<String>,
    salt_hex: Option<String>,
    salt_file: Option<String>,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    tag_length: u32,
    out_file: Option<String>,
    raw: bool,
) {
    let interactive = in_file.is_none();

    let password = match in_file
        .as_deref()
        .map(input::read_file)
        .unwrap_or_else(input::read_stdin)
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("비밀번호 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let salt_bytes = load_salt(salt_hex, salt_file);

    let argon = match Argon2id::new(time_cost, memory_cost, parallelism, tag_length) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Argon2id 파라미터 오류: {e}");
            std::process::exit(1);
        }
    };

    let tag = match argon.hash(password.as_slice(), &salt_bytes, &[], &[]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argon2id 해시 오류: {e}");
            std::process::exit(1);
        }
    };

    let result = if raw { tag } else { hex_encode(tag) };
    input::write_output(result, out_file.as_deref(), interactive);
}

fn load_salt(salt_hex: Option<String>, salt_file: Option<String>) -> Vec<u8> {
    if let Some(hex) = salt_hex {
        let hex_bytes = hex.as_bytes();
        let mut hex_buf = match SecureBuffer::new_owned(hex_bytes.len()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("메모리 할당 오류: {e}");
                std::process::exit(1);
            }
        };
        hex_buf.as_mut_slice().copy_from_slice(hex_bytes);
        match entlib_native_hex::decode(&hex_buf) {
            Ok(b) => return b.as_slice().to_vec(),
            Err(e) => {
                eprintln!("솔트 hex 디코딩 오류: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(path) = salt_file {
        match input::read_file(&path) {
            Ok(b) => return b.as_slice().to_vec(),
            Err(e) => {
                eprintln!("솔트 파일 읽기 오류: {e}");
                std::process::exit(1);
            }
        }
    }
    eprintln!("오류: --salt 또는 --salt-file 중 하나를 지정해야 합니다");
    std::process::exit(1);
}
