use crate::input;
use clap::Subcommand;
use entlib_native_pkcs8::{
    Algorithm, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, Pkcs8Params,
};
use entlib_native_rng::{DrbgError, HashDRBGSHA256};

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// 개인 키를 PKCS#8 EncryptedPrivateKeyInfo PEM으로 암호화
    Encrypt {
        /// 알고리즘 (ml-dsa-44 | ml-dsa-65 | ml-dsa-87)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 키 바이트 입력 파일 (필수)
        #[arg(long)]
        key_file: String,
        /// PEM 출력 파일 (생략 시 stdout)
        #[arg(long)]
        out_file: Option<String>,
        /// Argon2id 시간 비용 (기본: 2)
        #[arg(long, default_value_t = DEFAULT_TIME_COST)]
        time_cost: u32,
        /// Argon2id 메모리 비용 KiB (기본: 19456)
        #[arg(long, default_value_t = DEFAULT_MEMORY_COST)]
        memory_cost: u32,
        /// Argon2id 병렬성 (기본: 1)
        #[arg(long, default_value_t = DEFAULT_PARALLELISM)]
        parallelism: u32,
    },
    /// PKCS#8 EncryptedPrivateKeyInfo PEM에서 개인 키 복호화
    Decrypt {
        /// 암호화된 PEM 입력 파일 (필수)
        #[arg(long)]
        in_file: String,
        /// 키 바이트 출력 파일 (생략 시 stdout)
        #[arg(long)]
        out_file: Option<String>,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Encrypt {
            algorithm,
            key_file,
            out_file,
            time_cost,
            memory_cost,
            parallelism,
        } => run_encrypt(
            algorithm,
            key_file,
            out_file,
            time_cost,
            memory_cost,
            parallelism,
        ),
        Ops::Decrypt { in_file, out_file } => run_decrypt(in_file, out_file),
    }
}

fn run_encrypt(
    algorithm: String,
    key_file: String,
    out_file: Option<String>,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) {
    let algo = match Algorithm::from_name(&algorithm) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("오류: {e} — 지원 알고리즘: ml-dsa-44, ml-dsa-65, ml-dsa-87");
            std::process::exit(1);
        }
    };

    let key_bytes = match input::read_file(&key_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("키 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let passphrase = match input::read_passphrase("패스프레이즈: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("패스프레이즈 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let (salt, nonce) = match generate_salt_nonce() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("난수 생성 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let params = Pkcs8Params::new(time_cost, memory_cost, parallelism, salt, nonce);

    let pem = match entlib_native_pkcs8::encrypt_pem(
        algo,
        key_bytes.as_slice(),
        passphrase.as_slice(),
        &params,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("암호화 오류: {e}");
            std::process::exit(1);
        }
    };

    input::write_output(pem, out_file.as_deref(), false);
}

fn run_decrypt(in_file: String, out_file: Option<String>) {
    let pem = match input::read_file(&in_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("입력 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let passphrase = match input::read_passphrase("패스프레이즈: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("패스프레이즈 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let (algo, key_buf) =
        match entlib_native_pkcs8::decrypt_pem(pem.as_slice(), passphrase.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("복호화 오류: {e}");
                std::process::exit(1);
            }
        };

    eprintln!("알고리즘: {}", algo.name());
    input::write_output(key_buf, out_file.as_deref(), false);
}

fn generate_salt_nonce() -> Result<([u8; 16], [u8; 12]), DrbgError> {
    let mut drbg = HashDRBGSHA256::new_from_os(Some(b"entlib-pkcs8"))?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    drbg.generate(&mut salt, None)?;
    drbg.generate(&mut nonce, None)?;
    Ok((salt, nonce))
}
