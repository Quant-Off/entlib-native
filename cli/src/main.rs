use clap::{Parser, Subcommand};

mod cmd;
mod input;

#[derive(Parser)]
#[command(name = "entlib-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Base64 인코딩/디코딩
    Base64 {
        #[command(subcommand)]
        op: cmd::base64::Ops,
    },
    /// Hex 인코딩/디코딩
    Hex {
        #[command(subcommand)]
        op: cmd::hex::Ops,
    },
    /// SHA-2 해시 (SHA-224/256/384/512)
    Sha2 {
        #[command(subcommand)]
        op: cmd::sha2::Ops,
    },
    /// SHA-3 해시 (SHA3-224/256/384/512, SHAKE128/256)
    Sha3 {
        #[command(subcommand)]
        op: cmd::sha3::Ops,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Base64 { op } => cmd::base64::run(op),
        Commands::Hex { op } => cmd::hex::run(op),
        Commands::Sha2 { op } => cmd::sha2::run(op),
        Commands::Sha3 { op } => cmd::sha3::run(op),
    }
}