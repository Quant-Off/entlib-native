use crate::input;
use clap::Subcommand;
use entlib_native_base64::{decode, encode};

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// Base64 인코딩
    Encode {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
    },
    /// Base64 디코딩
    Decode {
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Encode { in_file, out_file } => {
            let interactive = in_file.is_none();
            let buf = match in_file.as_deref().map(input::read_file).unwrap_or_else(input::read_stdin) {
                Ok(b) => b,
                Err(e) => { eprintln!("오류: {e}"); std::process::exit(1); }
            };
            match encode(&buf) {
                Ok(result) => input::write_output(result, out_file.as_deref(), interactive),
                Err(e) => { eprintln!("인코딩 오류: {e}"); std::process::exit(1); }
            }
        }
        Ops::Decode { in_file, out_file } => {
            let interactive = in_file.is_none();
            let buf = match in_file.as_deref().map(input::read_file).unwrap_or_else(input::read_stdin) {
                Ok(b) => b,
                Err(e) => { eprintln!("오류: {e}"); std::process::exit(1); }
            };
            match decode(&buf) {
                Ok(result) => input::write_output(result, out_file.as_deref(), interactive),
                Err(e) => { eprintln!("디코딩 오류: {e}"); std::process::exit(1); }
            }
        }
    }
}
