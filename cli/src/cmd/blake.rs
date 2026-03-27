use super::hex_encode;
use crate::input;
use clap::Subcommand;
use entlib_native_blake::{Blake2b, Blake3};

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// BLAKE2b (RFC 7693, 최대 512-bit 다이제스트)
    #[command(name = "2b")]
    Blake2b {
        /// 출력 바이트 수 (1–64, 기본: 32)
        #[arg(long, default_value_t = 32)]
        output_len: usize,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        /// raw 바이너리 출력 (기본: hex)
        #[arg(long)]
        raw: bool,
    },
    /// BLAKE3 (32-byte 기본 출력, XOF 지원)
    #[command(name = "3")]
    Blake3 {
        /// 출력 바이트 수 (기본: 32)
        #[arg(long, default_value_t = 32)]
        output_len: usize,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        /// raw 바이너리 출력 (기본: hex)
        #[arg(long)]
        raw: bool,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Blake2b {
            output_len,
            in_file,
            out_file,
            raw,
        } => {
            if !(1..=64).contains(&output_len) {
                eprintln!("오류: output_len은 1–64 범위여야 합니다");
                std::process::exit(1);
            }
            let interactive = in_file.is_none();
            let buf = match in_file
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
            let mut hasher = Blake2b::new(output_len);
            hasher.update(buf.as_slice());
            let digest = match hasher.finalize() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("해시 오류: {e}");
                    std::process::exit(1);
                }
            };
            let result = if raw { digest } else { hex_encode(digest) };
            input::write_output(result, out_file.as_deref(), interactive);
        }
        Ops::Blake3 {
            output_len,
            in_file,
            out_file,
            raw,
        } => {
            if output_len == 0 {
                eprintln!("오류: output_len은 1 이상이어야 합니다");
                std::process::exit(1);
            }
            let interactive = in_file.is_none();
            let buf = match in_file
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
            let mut hasher = Blake3::new();
            hasher.update(buf.as_slice());
            let digest = match hasher.finalize_xof(output_len) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("해시 오류: {e}");
                    std::process::exit(1);
                }
            };
            let result = if raw { digest } else { hex_encode(digest) };
            input::write_output(result, out_file.as_deref(), interactive);
        }
    }
}
