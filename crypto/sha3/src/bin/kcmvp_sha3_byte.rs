//! 얽힘 라이브러리(EntanglementLib) entlib-native 네이티브 SHA3 제품군 통합 KCMVP Byte-Oriented & Monte Carlo CAVP 검증 도구
//! 지원 알고리즘: SHA3_224, SHA3_256, SHA3_384, SHA3_512
//!
//! KCMVP 암호알고리즘 검증기준 V3.0에 따른 임의 메시지 검사(Monte Carlo) 규격 적용

use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};

use entlib_native_sha3::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

enum DynamicHasher {
    Sha224(SHA3_224),
    Sha256(SHA3_256),
    Sha384(SHA3_384),
    Sha512(SHA3_512),
}

impl DynamicHasher {
    fn new(algo: &str) -> Self {
        match algo {
            "224" | "SHA3_224" => DynamicHasher::Sha224(SHA3_224::new()),
            "256" | "SHA3_256" => DynamicHasher::Sha256(SHA3_256::new()),
            "384" | "SHA3_384" => DynamicHasher::Sha384(SHA3_384::new()),
            "512" | "SHA3_512" => DynamicHasher::Sha512(SHA3_512::new()),
            _ => panic!("지원하지 않는 알고리즘입니다. (224, 256, 384, 512 중 택일): {}", algo),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            DynamicHasher::Sha224(h) => h.update(data),
            DynamicHasher::Sha256(h) => h.update(data),
            DynamicHasher::Sha384(h) => h.update(data),
            DynamicHasher::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            DynamicHasher::Sha224(h) => h.finalize(),
            DynamicHasher::Sha256(h) => h.finalize(),
            DynamicHasher::Sha384(h) => h.finalize(),
            DynamicHasher::Sha512(h) => h.finalize(),
        }
    }
}

/// KCMVP 규격: N = floor(r/n) + 1 계산 함수
fn get_kcmvp_n(algo: &str) -> usize {
    match algo {
        "224" | "SHA3_224" => (1152 / 224) + 1, // 6
        "256" | "SHA3_256" => (1088 / 256) + 1, // 5
        "384" | "SHA3_384" => (832 / 384) + 1,  // 3
        "512" | "SHA3_512" => (576 / 512) + 1,  // 2
        _ => panic!("지원하지 않는 알고리즘"),
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("사용법: {} <224|256|384|512> <SMT.rsp | LMT.rsp | MCT.rsp> [output.rsp]", args[0]);
        std::process::exit(1);
    }

    let algo_str = &args[1];
    let input_path = &args[2];
    let output_path = args.get(3);

    println!("[KCMVP] SHA3-{} 검증 시작", algo_str);

    let file = File::open(input_path)?;
    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let mut output_lines = Vec::new();
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut i = 0;

    let mut current_mc_md: Vec<u8> = Vec::new();

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with("Len = ") {
            // [1] Short / Long Message 테스트 블록 (NIST와 동일)
            output_lines.push(lines[i].clone());
            let len: usize = line.strip_prefix("Len = ").unwrap().trim().parse().unwrap();

            i += 1;
            let msg_hex = lines[i].trim().strip_prefix("Msg = ").unwrap_or("").trim().to_string();
            output_lines.push(lines[i].clone());

            i += 1;
            let expected_md = if i < lines.len() && lines[i].trim().starts_with("MD = ") {
                lines[i].trim().strip_prefix("MD = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            let mut hasher = DynamicHasher::new(algo_str);
            let msg_data: Vec<u8> = if len == 0 {
                vec![]
            } else {
                let byte_len = len / 8;
                let decoded = hex::decode(&msg_hex).expect("Msg hex decode 실패");
                decoded[0..byte_len].to_vec()
            };

            hasher.update(&msg_data);
            let digest = hasher.finalize();
            let computed_md = hex::encode(&digest).to_uppercase();

            output_lines.push(format!("MD = {}", computed_md));

            if !expected_md.is_empty() {
                total += 1;
                if computed_md == expected_md { passed += 1; }
                else { eprintln!("FAIL  Len = {}", len); }
            }
        } else if line.starts_with("Seed = ") {
            // [2] Monte Carlo Seed 초기화
            output_lines.push(lines[i].clone());
            let seed_hex = line.strip_prefix("Seed = ").unwrap().trim();
            current_mc_md = hex::decode(seed_hex).expect("Seed hex decode 실패");
        } else if line.starts_with("COUNT = ") {
            // [3] Monte Carlo COUNT 루프
            output_lines.push(lines[i].clone());
            let count_str = line.strip_prefix("COUNT = ").unwrap().trim();

            i += 1;
            let expected_md = if i < lines.len() && lines[i].trim().starts_with("MD = ") {
                lines[i].trim().strip_prefix("MD = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            // KCMVP 임의 메시지 검사 파라미터 적용
            let n_val = get_kcmvp_n(algo_str);

            // MD_{0} ~ MD_{N-1} 까지 Seed로 배열 초기화
            let mut md_array: Vec<Vec<u8>> = vec![current_mc_md.clone(); n_val];

            for k in n_val..(1000 + n_val) {
                let mut hasher = DynamicHasher::new(algo_str);

                // 순서대로 hasher에 주입하여 Concatenation (Msg_i = MD_{k-N} || ... || MD_{k-1})
                for j in 0..n_val {
                    hasher.update(&md_array[k - n_val + j]);
                }

                let digest = hasher.finalize();
                md_array.push(digest);
            }

            // 다음 COUNT 루프를 위해 Seed 갱신 (MD_{1000+N-1})
            current_mc_md = md_array[1000 + n_val - 1].clone();

            let computed_md = hex::encode(&current_mc_md).to_uppercase();
            output_lines.push(format!("MD = {}", computed_md));

            if !expected_md.is_empty() {
                total += 1;
                if computed_md == expected_md { passed += 1; }
                else { eprintln!("FAIL  Monte Carlo COUNT = {}", count_str); }
            }
        } else {
            output_lines.push(lines[i].clone());
        }
        i += 1;
    }

    println!("\n=== KCMVP CAVP Byte-Oriented 검증 결과 ===");
    println!("총 테스트 케이스 : {}", total);
    println!("PASS           : {}", passed);
    println!("FAIL           : {}", total - passed);

    if let Some(out_path) = output_path {
        let mut f = File::create(out_path)?;
        for line in &output_lines { writeln!(f, "{}", line)?; }
        println!("응답 파일 생성: {}", out_path);
    }

    Ok(())
}