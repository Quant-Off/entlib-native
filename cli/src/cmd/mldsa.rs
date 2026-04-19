use crate::input;
use clap::Subcommand;
use entlib_native_mldsa::{HashDRBGRng, MLDSA, MLDSAParameter, MLDSAPrivateKey, MLDSAPublicKey};
use entlib_native_pkcs8::{
    Algorithm, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, Pkcs8Params,
};
use entlib_native_rng::{DrbgError, HashDRBGSHA256};

fn parse_param(s: &str) -> Result<MLDSAParameter, String> {
    match s {
        "ml-dsa-44" | "mldsa44" | "ML-DSA-44" => Ok(MLDSAParameter::MLDSA44),
        "ml-dsa-65" | "mldsa65" | "ML-DSA-65" => Ok(MLDSAParameter::MLDSA65),
        "ml-dsa-87" | "mldsa87" | "ML-DSA-87" => Ok(MLDSAParameter::MLDSA87),
        _ => Err(format!("알 수 없는 알고리즘: {s}")),
    }
}

#[derive(Subcommand)]
pub(crate) enum Ops {
    /// ML-DSA 키 쌍 생성 및 추출
    Keygen {
        /// 파라미터 셋 (ml-dsa-44 | ml-dsa-65 | ml-dsa-87)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 공개 키 출력 파일 (생략 시 stdout)
        #[arg(long)]
        pk_out: Option<String>,
        /// 비밀 키 출력 파일 (생략 시 stdout)
        #[arg(long)]
        sk_out: Option<String>,
        /// PKCS#8 PEM 형식으로 출력 (비밀 키: EncryptedPrivateKeyInfo, 공개 키: SubjectPublicKeyInfo)
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
    /// ML-DSA 서명 생성
    Sign {
        /// 파라미터 셋 (ml-dsa-44 | ml-dsa-65 | ml-dsa-87)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 비밀 키 파일
        #[arg(long)]
        sk_file: String,
        /// 서명할 메시지 파일 (생략 시 stdin)
        #[arg(long)]
        msg_file: Option<String>,
        /// 컨텍스트 문자열 (기본: 빈 문자열)
        #[arg(long, default_value = "")]
        ctx: String,
        /// 서명 출력 파일 (생략 시 stdout)
        #[arg(long)]
        out_file: Option<String>,
    },
    /// ML-DSA 서명 검증
    Verify {
        /// 파라미터 셋 (ml-dsa-44 | ml-dsa-65 | ml-dsa-87)
        #[arg(long, short = 'a')]
        algorithm: String,
        /// 공개 키 파일
        #[arg(long)]
        pk_file: String,
        /// 서명 파일
        #[arg(long)]
        sig_file: String,
        /// 검증할 메시지 파일 (생략 시 stdin)
        #[arg(long)]
        msg_file: Option<String>,
        /// 서명 시 사용한 컨텍스트 문자열 (기본: 빈 문자열)
        #[arg(long, default_value = "")]
        ctx: String,
    },
}

pub(crate) fn run(op: Ops) {
    match op {
        Ops::Keygen {
            algorithm,
            pk_out,
            sk_out,
            pkcs8,
            time_cost,
            memory_cost,
            parallelism,
        } => run_keygen(
            algorithm,
            pk_out,
            sk_out,
            pkcs8,
            time_cost,
            memory_cost,
            parallelism,
        ),
        Ops::Sign {
            algorithm,
            sk_file,
            msg_file,
            ctx,
            out_file,
        } => run_sign(algorithm, sk_file, msg_file, ctx, out_file),
        Ops::Verify {
            algorithm,
            pk_file,
            sig_file,
            msg_file,
            ctx,
        } => run_verify(algorithm, pk_file, sig_file, msg_file, ctx),
    }
}

fn run_keygen(
    algorithm: String,
    pk_out: Option<String>,
    sk_out: Option<String>,
    pkcs8: bool,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e} — 지원 알고리즘: ml-dsa-44, ml-dsa-65, ml-dsa-87");
            std::process::exit(1);
        }
    };

    let mut rng = match HashDRBGRng::new_from_os(Some(b"entlib-mldsa-keygen")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RNG 초기화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let (pk, sk) = match MLDSA::key_gen(param, &mut rng) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("키 생성 오류: {e:?}");
            std::process::exit(1);
        }
    };

    if pkcs8 {
        run_keygen_pkcs8(
            param,
            pk.as_bytes(),
            sk.as_bytes(),
            pk_out,
            sk_out,
            time_cost,
            memory_cost,
            parallelism,
        );
        return;
    }

    // 공개 키 출력
    write_bytes(pk.as_bytes(), pk_out.as_deref(), "공개 키");

    // 비밀 키 출력
    write_bytes(sk.as_bytes(), sk_out.as_deref(), "비밀 키");
}

fn param_to_algorithm(param: MLDSAParameter) -> Algorithm {
    match param {
        MLDSAParameter::MLDSA44 => Algorithm::MLDSA44,
        MLDSAParameter::MLDSA65 => Algorithm::MLDSA65,
        MLDSAParameter::MLDSA87 => Algorithm::MLDSA87,
    }
}

fn generate_salt_nonce() -> Result<([u8; 16], [u8; 12]), DrbgError> {
    let mut drbg = HashDRBGSHA256::new_from_os(Some(b"entlib-mldsa-pkcs8"))?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    drbg.generate(&mut salt, None)?;
    drbg.generate(&mut nonce, None)?;
    Ok((salt, nonce))
}

#[allow(clippy::too_many_arguments)]
fn run_keygen_pkcs8(
    param: MLDSAParameter,
    pk_bytes: &[u8],
    sk_bytes: &[u8],
    pk_out: Option<String>,
    sk_out: Option<String>,
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

    let sk_pem =
        match entlib_native_pkcs8::encrypt_pem(algo, sk_bytes, passphrase.as_slice(), &params) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("비밀 키 암호화 오류: {e}");
                std::process::exit(1);
            }
        };

    let pk_pem = match entlib_native_pkcs8::encode_spki_pem(algo, pk_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("공개 키 인코딩 오류: {e}");
            std::process::exit(1);
        }
    };

    write_bytes(pk_pem.as_slice(), pk_out.as_deref(), "공개 키 PEM");
    write_bytes(sk_pem.as_slice(), sk_out.as_deref(), "비밀 키 PEM");
}

fn run_sign(
    algorithm: String,
    sk_file: String,
    msg_file: Option<String>,
    ctx: String,
    out_file: Option<String>,
) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e}");
            std::process::exit(1);
        }
    };

    let sk_bytes = match input::read_file(&sk_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("비밀 키 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let sk = match MLDSAPrivateKey::from_bytes(param, sk_bytes.as_slice()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("비밀 키 파싱 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let msg = match msg_file
        .as_deref()
        .map(input::read_file)
        .unwrap_or_else(input::read_stdin)
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("메시지 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let mut rng = match HashDRBGRng::new_from_os(Some(b"entlib-mldsa-sign")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RNG 초기화 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let sig = match MLDSA::sign(&sk, msg.as_slice(), ctx.as_bytes(), &mut rng) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("서명 오류: {e:?}");
            std::process::exit(1);
        }
    };

    write_bytes(sig.as_slice(), out_file.as_deref(), "서명");
}

fn run_verify(
    algorithm: String,
    pk_file: String,
    sig_file: String,
    msg_file: Option<String>,
    ctx: String,
) {
    let param = match parse_param(&algorithm) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("오류: {e}");
            std::process::exit(1);
        }
    };

    let pk_bytes = match input::read_file(&pk_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("공개 키 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let pk = match MLDSAPublicKey::from_bytes(param, pk_bytes.as_slice().to_vec()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("공개 키 파싱 오류: {e:?}");
            std::process::exit(1);
        }
    };

    let sig = match input::read_file(&sig_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("서명 파일 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    let msg = match msg_file
        .as_deref()
        .map(input::read_file)
        .unwrap_or_else(input::read_stdin)
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("메시지 읽기 오류: {e}");
            std::process::exit(1);
        }
    };

    match MLDSA::verify(&pk, msg.as_slice(), sig.as_slice(), ctx.as_bytes()) {
        Ok(true) => eprintln!("서명 유효"),
        Ok(false) => {
            eprintln!("서명 무효");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("검증 오류: {e:?}");
            std::process::exit(1);
        }
    }
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
