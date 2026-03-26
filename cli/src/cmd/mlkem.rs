use crate::input;
use clap::Subcommand;
use entlib_native_mlkem::{
    HashDRBGRng, MLKEM, MLKEMDecapsulationKey, MLKEMEncapsulationKey, MLKEMParameter,
};
use entlib_native_pkcs8::{
    Algorithm, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, Pkcs8Params,
};
use entlib_native_rng::{DrbgError, HashDRBGSHA256};

fn parse_param(s: &str) -> Result<MLKEMParameter, String> {
    match s {
        "ml-kem-512" | "mlkem512" | "ML-KEM-512" => Ok(MLKEMParameter::MLKEM512),
        "ml-kem-768" | "mlkem768" | "ML-KEM-768" => Ok(MLKEMParameter::MLKEM768),
        "ml-kem-1024" | "mlkem1024" | "ML-KEM-1024" => Ok(MLKEMParameter::MLKEM1024),
        _ => Err(format!("알 수 없는 알고리즘: {s}")),
    }
}

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// ML-KEM 키 쌍 생성 (캡슐화 키 + 역캡슐화 키)
    Keygen {
        /// 파라미터 셋 (ml-kem-512 | ml-kem-768 | ml-kem-1024)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 캡슐화 키 출력 파일 (생략 시 stdout)
        #[arg(long)]
        ek_out: Option<String>,
        /// 역캡슐화 키 출력 파일 (생략 시 stdout)
        #[arg(long)]
        dk_out: Option<String>,
        /// PKCS#8 PEM 형식으로 출력 (역캡슐화 키: EncryptedPrivateKeyInfo, 캡슐화 키: SubjectPublicKeyInfo)
        #[arg(long)]
        pkcs8: bool,
        /// Argon2id 시간 비용 (기본: 2, --pkcs8 활성화 시에만 적용)
        #[arg(long, default_value_t = DEFAULT_TIME_COST)]
        time_cost: u32,
        /// Argon2id 메모리 비용 KiB (기본: 19456, --pkcs8 활성화 시에만 적용)
        #[arg(long, default_value_t = DEFAULT_MEMORY_COST)]
        memory_cost: u32,
        /// Argon2id 병렬성 (기본: 1, --pkcs8 활성화 시에만 적용)
        #[arg(long, default_value_t = DEFAULT_PARALLELISM)]
        parallelism: u32,
    },
    /// ML-KEM 캡슐화 (공유 비밀 + 암호문 생성)
    Encaps {
        /// 파라미터 셋 (ml-kem-512 | ml-kem-768 | ml-kem-1024)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 캡슐화 키 파일
        #[arg(long)]
        ek_file: String,
        /// 공유 비밀 출력 파일 (생략 시 stdout)
        #[arg(long)]
        ss_out: Option<String>,
        /// 암호문 출력 파일 (생략 시 stdout)
        #[arg(long)]
        ct_out: Option<String>,
    },
    /// ML-KEM 역캡슐화 (공유 비밀 복원)
    Decaps {
        /// 파라미터 셋 (ml-kem-512 | ml-kem-768 | ml-kem-1024)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 역캡슐화 키 파일
        #[arg(long)]
        dk_file: String,
        /// 암호문 파일
        #[arg(long)]
        ct_file: String,
        /// 공유 비밀 출력 파일 (생략 시 stdout)
        #[arg(long)]
        ss_out: Option<String>,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Keygen {
            algorithm,
            ek_out,
            dk_out,
            pkcs8,
            time_cost,
            memory_cost,
            parallelism,
        } => run_keygen(
            algorithm,
            ek_out,
            dk_out,
            pkcs8,
            time_cost,
            memory_cost,
            parallelism,
        ),
        Ops::Encaps {
            algorithm,
            ek_file,
            ss_out,
            ct_out,
        } => run_encaps(algorithm, ek_file, ss_out, ct_out),
        Ops::Decaps {
            algorithm,
            dk_file,
            ct_file,
            ss_out,
        } => run_decaps(algorithm, dk_file, ct_file, ss_out),
    }
}

fn run_keygen(
    algorithm: String,
    ek_out: Option<String>,
    dk_out: Option<String>,
    pkcs8: bool,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e} — 지원 알고리즘: ml-kem-512, ml-kem-768, ml-kem-1024");
            std::process::exit(1);
        }
    };

    let mut rng = match HashDRBGRng::new_from_os(Some(b"entlib-mlkem-keygen")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RNG 초기화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let (ek, dk) = match MLKEM::key_gen(param, &mut rng) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("키 생성 오류: {e:?}");
            std::process::exit(1);
        }
    };

    if pkcs8 {
        run_keygen_pkcs8(
            param,
            ek.as_bytes(),
            dk.as_bytes(),
            ek_out,
            dk_out,
            time_cost,
            memory_cost,
            parallelism,
        );
        return;
    }

    write_bytes(ek.as_bytes(), ek_out.as_deref(), "캡슐화 키");
    write_bytes(dk.as_bytes(), dk_out.as_deref(), "역캡슐화 키");
}

fn param_to_algorithm(param: MLKEMParameter) -> Algorithm {
    match param {
        MLKEMParameter::MLKEM512 => Algorithm::MLKEM512,
        MLKEMParameter::MLKEM768 => Algorithm::MLKEM768,
        MLKEMParameter::MLKEM1024 => Algorithm::MLKEM1024,
    }
}

fn generate_salt_nonce() -> Result<([u8; 16], [u8; 12]), DrbgError> {
    let mut drbg = HashDRBGSHA256::new_from_os(Some(b"entlib-mlkem-pkcs8"))?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    drbg.generate(&mut salt, None)?;
    drbg.generate(&mut nonce, None)?;
    Ok((salt, nonce))
}

#[allow(clippy::too_many_arguments)]
fn run_keygen_pkcs8(
    param: MLKEMParameter,
    ek_bytes: &[u8],
    dk_bytes: &[u8],
    ek_out: Option<String>,
    dk_out: Option<String>,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) {
    let algo = param_to_algorithm(param);

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

    let dk_pem =
        match entlib_native_pkcs8::encrypt_pem(algo, dk_bytes, passphrase.as_slice(), &params) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("역캡슐화 키 암호화 오류: {e}");
                std::process::exit(1);
            }
        };

    let ek_pem = match entlib_native_pkcs8::encode_spki_pem(algo, ek_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("캡슐화 키 인코딩 오류: {e}");
            std::process::exit(1);
        }
    };

    write_bytes(ek_pem.as_slice(), ek_out.as_deref(), "캡슐화 키 PEM");
    write_bytes(dk_pem.as_slice(), dk_out.as_deref(), "역캡슐화 키 PEM");
}

fn run_encaps(algorithm: String, ek_file: String, ss_out: Option<String>, ct_out: Option<String>) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e}");
            std::process::exit(1);
        }
    };

    let ek_bytes = match input::read_file(&ek_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("캡슐화 키 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let ek = match MLKEMEncapsulationKey::from_bytes(param, ek_bytes.as_slice().to_vec()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("캡슐화 키 파싱 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let mut rng = match HashDRBGRng::new_from_os(Some(b"entlib-mlkem-encaps")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RNG 초기화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let (ss, ct) = match MLKEM::encaps(&ek, &mut rng) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("캡슐화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    write_bytes(ss.as_slice(), ss_out.as_deref(), "공유 비밀");
    write_bytes(&ct, ct_out.as_deref(), "암호문");
}

fn run_decaps(algorithm: String, dk_file: String, ct_file: String, ss_out: Option<String>) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e}");
            std::process::exit(1);
        }
    };

    let dk_bytes = match input::read_file(&dk_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("역캡슐화 키 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let dk = match MLKEMDecapsulationKey::from_bytes(param, dk_bytes.as_slice()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("역캡슐화 키 파싱 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let ct_bytes = match input::read_file(&ct_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("암호문 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let ss = match MLKEM::decaps(&dk, ct_bytes.as_slice()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("역캡슐화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    write_bytes(ss.as_slice(), ss_out.as_deref(), "공유 비밀");
}

fn write_bytes(data: &[u8], path: Option<&str>, label: &str) {
    use std::io::Write;
    if let Some(p) = path {
        if let Err(e) = std::fs::write(p, data) {
            eprintln!("{label} 파일 쓰기 오류: {e}");
            std::process::exit(1);
        }
    } else if let Err(e) = std::io::stdout().write_all(data) {
        eprintln!("{label} 출력 오류: {e}");
        std::process::exit(1);
    }
}
