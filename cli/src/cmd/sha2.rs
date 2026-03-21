use super::hex_encode;
use crate::input;
use clap::Subcommand;
use entlib_native_sha2::api::{SHA224, SHA256, SHA384, SHA512};

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// SHA-224 (112-bit security)
    Sha224 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        /// raw 바이너리 출력 (기본: hex)
        #[arg(long)]
        raw: bool,
    },
    /// SHA-256 (128-bit security)
    Sha256 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// SHA-384 (192-bit security)
    Sha384 {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        raw: bool,
    },
    /// SHA-512 (256-bit security)
    Sha512 {
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
        let buf = match $in_file.as_deref().map(input::read_file).unwrap_or_else(input::read_stdin) {
            Ok(b) => b,
            Err(e) => { eprintln!("오류: {e}"); std::process::exit(1); }
        };
        let mut hasher = $hasher;
        hasher.update(buf.as_slice());
        let digest = match hasher.finalize() {
            Ok(d) => d,
            Err(e) => { eprintln!("해시 오류: {e}"); std::process::exit(1); }
        };
        let result = if $raw {
            digest
        } else {
            hex_encode(digest)
        };
        input::write_output(result, $out_file.as_deref(), interactive);
    }};
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Sha224 { in_file, out_file, raw } => run_hash!(SHA224::new(), in_file, out_file, raw),
        Ops::Sha256 { in_file, out_file, raw } => run_hash!(SHA256::new(), in_file, out_file, raw),
        Ops::Sha384 { in_file, out_file, raw } => run_hash!(SHA384::new(), in_file, out_file, raw),
        Ops::Sha512 { in_file, out_file, raw } => run_hash!(SHA512::new(), in_file, out_file, raw),
    }
}