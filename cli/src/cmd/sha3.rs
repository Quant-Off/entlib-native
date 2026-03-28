use super::hex_encode;
use crate::input;
use clap::Subcommand;
use entlib_native_sha3::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use entlib_native_sha3::file::{sha3_224 as sha3_224_file, sha3_256 as sha3_256_file, sha3_384 as sha3_384_file, sha3_512 as sha3_512_file};

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// SHA3-224 (112-bit security)
    Sha3_224 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        /// raw 바이너리 출력 (기본: hex)
        #[arg(long)]
        raw: bool,
    },
    /// SHA3-256 (128-bit security)
    Sha3_256 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// SHA3-384 (192-bit security)
    Sha3_384 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// SHA3-512 (256-bit security)
    Sha3_512 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// 파일 스트리밍 해시 (SHA3-224/256/384/512)
    HashFile {
        /// SHA3 변형 (224, 256, 384, 512)
        #[arg(long, default_value_t = 256)]
        bits: u16,
        /// 해시할 파일 경로
        file: String,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// XOF SHAKE128 (128-bit security, 가변 출력 길이)
    Shake128 {
        /// 출력 바이트 수
        #[arg(long)]
        output_len: usize,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// XOF SHAKE256 (256-bit security, 가변 출력 길이)
    Shake256 {
        /// 출력 바이트 수
        #[arg(long)]
        output_len: usize,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
}

macro_rules! run_hash {
    ($hasher:expr, $in_file:expr, $out_file:expr, $raw:expr) => {{
        let interactive = $in_file.is_none();
        let buf = match $in_file
            .as_deref()
            .map(input::read_file)
            .unwrap_or_else(input::read_stdin)
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("오류: {e}");
                std::process::exit(1);
            }
        };
        let mut hasher = $hasher;
        hasher.update(buf.as_slice());
        let digest = match hasher.finalize() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("해시 오류: {e}");
                std::process::exit(1);
            }
        };
        let result = if $raw { digest } else { hex_encode(digest) };
        input::write_output(result, $out_file.as_deref(), interactive);
    }};
}

macro_rules! run_xof {
    ($hasher:expr, $output_len:expr, $in_file:expr, $out_file:expr, $raw:expr) => {{
        let interactive = $in_file.is_none();
        let buf = match $in_file
            .as_deref()
            .map(input::read_file)
            .unwrap_or_else(input::read_stdin)
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("오류: {e}");
                std::process::exit(1);
            }
        };
        let mut hasher = $hasher;
        hasher.update(buf.as_slice());
        let digest = match hasher.finalize($output_len) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("해시 오류: {e}");
                std::process::exit(1);
            }
        };
        let result = if $raw { digest } else { hex_encode(digest) };
        input::write_output(result, $out_file.as_deref(), interactive);
    }};
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::HashFile {
            bits,
            file,
            out_file,
            raw,
        } => {
            let digest = match bits {
                224 => sha3_224_file::hash_file(&file),
                256 => sha3_256_file::hash_file(&file),
                384 => sha3_384_file::hash_file(&file),
                512 => sha3_512_file::hash_file(&file),
                _ => {
                    eprintln!("지원하지 않는 비트 길이: {bits} (224, 256, 384, 512 중 선택)");
                    std::process::exit(1);
                }
            };
            match digest {
                Ok(d) => {
                    let result = if raw { d } else { hex_encode(d) };
                    input::write_output(result, out_file.as_deref(), false);
                }
                Err(e) => {
                    eprintln!("파일 해시 오류: {e}");
                    std::process::exit(1);
                }
            }
        }
        Ops::Sha3_224 {
            in_file,
            out_file,
            raw,
        } => run_hash!(SHA3_224::new(), in_file, out_file, raw),
        Ops::Sha3_256 {
            in_file,
            out_file,
            raw,
        } => run_hash!(SHA3_256::new(), in_file, out_file, raw),
        Ops::Sha3_384 {
            in_file,
            out_file,
            raw,
        } => run_hash!(SHA3_384::new(), in_file, out_file, raw),
        Ops::Sha3_512 {
            in_file,
            out_file,
            raw,
        } => run_hash!(SHA3_512::new(), in_file, out_file, raw),
        Ops::Shake128 {
            output_len,
            in_file,
            out_file,
            raw,
        } => run_xof!(SHAKE128::new(), output_len, in_file, out_file, raw),
        Ops::Shake256 {
            output_len,
            in_file,
            out_file,
            raw,
        } => run_xof!(SHAKE256::new(), output_len, in_file, out_file, raw),
    }
}
