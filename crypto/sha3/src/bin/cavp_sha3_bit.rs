//! 얽힘 라이브러리(EntanglementLib) entlib-native 네이티브 SHA3 제품군 통합 Bit-Oriented & Monte Carlo CAVP 검증 도구
//! 지원 알고리즘: SHA3_224, SHA3_256, SHA3_384, SHA3_512

use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};

use entlib_native_sha3::api::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

/// 런타임에 해시 알고리즘을 동적으로 선택하기 위한 래퍼 열거형
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
// cargo run --bin cavp_sha3_bit -- 384 test-vectors/sha-3bittestvectors/SHA3_384ShortMsg.rsp && cargo run --bin cavp_sha3_bit -- 384 test-vectors/sha-3bittestvectors/SHA3_384LongMsg.rsp && cargo run --bin cavp_sha3_bit -- 384 test-vectors/sha-3bittestvectors/SHA3_384Monte.rsp && cargo run --bin cavp_sha3_bit -- 512 test-vectors/sha-3bittestvectors/SHA3_512ShortMsg.rsp && cargo run --bin cavp_sha3_bit -- 512 test-vectors/sha-3bittestvectors/SHA3_512LongMsg.rsp && cargo run --bin cavp_sha3_bit -- 512 test-vectors/sha-3bittestvectors/SHA3_512Monte.rsp
    fn finalize(self) -> Vec<u8> {
        match self {
            DynamicHasher::Sha224(h) => h.finalize(),
            DynamicHasher::Sha256(h) => h.finalize(),
            DynamicHasher::Sha384(h) => h.finalize(),
            DynamicHasher::Sha512(h) => h.finalize(),
        }
    }

    fn finalize_bits(self, last_byte: u8, valid_bits: usize) -> Vec<u8> {
        match self {
            DynamicHasher::Sha224(h) => h.finalize_bits(last_byte, valid_bits),
            DynamicHasher::Sha256(h) => h.finalize_bits(last_byte, valid_bits),
            DynamicHasher::Sha384(h) => h.finalize_bits(last_byte, valid_bits),
            DynamicHasher::Sha512(h) => h.finalize_bits(last_byte, valid_bits),
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("사용법: {} <224|256|384|512> <ShortMsg.rsp | LongMsg.rsp | Monte.rsp> [output.rsp]", args[0]);
        std::process::exit(1);
    }

    let algo_str = &args[1];
    let input_path = &args[2];
    let output_path = args.get(3);

    println!("[NIST FIPS 202] SHA3-{} Bit-Oriented & Monte Carlo CAVP 검증 시작", algo_str);

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
            output_lines.push(lines[i].clone());
            let len_str = line.strip_prefix("Len = ").unwrap().trim();
            let len: usize = len_str.parse().expect("Len 파싱 실패");

            i += 1;
            let msg_line = lines[i].trim();
            let msg_hex = msg_line.strip_prefix("Msg = ").unwrap_or("").trim().to_string();
            output_lines.push(lines[i].clone());

            i += 1;
            let expected_md = if i < lines.len() && lines[i].trim().starts_with("MD = ") {
                lines[i].trim().strip_prefix("MD = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            let rem = len % 8;

            // 동적 해셔 인스턴스 생성
            let mut hasher = DynamicHasher::new(algo_str);
            let computed_md: String;

            if rem == 0 {
                let msg_data: Vec<u8> = if len == 0 {
                    vec![]
                } else {
                    let byte_len = len / 8;
                    let decoded = hex::decode(&msg_hex).expect("Msg hex decode 실패");
                    decoded[0..byte_len].to_vec()
                };

                hasher.update(&msg_data);
                let digest = hasher.finalize();
                computed_md = hex::encode(&digest).to_uppercase();
            } else {
                let byte_len = (len + 7) / 8;
                let decoded = hex::decode(&msg_hex).expect("Msg hex decode 실패");
                let mut data = decoded[0..byte_len.min(decoded.len())].to_vec();

                data[byte_len - 1] &= (1u8 << rem) - 1;

                let complete_bytes = &data[..byte_len - 1];
                hasher.update(complete_bytes);

                let last_byte = data[byte_len - 1];
                let digest = hasher.finalize_bits(last_byte, rem);

                computed_md = hex::encode(&digest).to_uppercase();
            }

            output_lines.push(format!("MD = {}", computed_md));

            if !expected_md.is_empty() {
                total += 1;
                if computed_md == expected_md {
                    passed += 1;
                } else {
                    eprintln!("FAIL  Len = {} bits", len);
                    eprintln!("   Expected: {}", expected_md);
                    eprintln!("   Computed: {}", computed_md);
                }
            }
        } else if line.starts_with("Seed = ") {
            output_lines.push(lines[i].clone());
            let seed_hex = line.strip_prefix("Seed = ").unwrap().trim();
            current_mc_md = hex::decode(seed_hex).expect("Seed hex decode 실패");

        } else if line.starts_with("COUNT = ") {
            output_lines.push(lines[i].clone());
            let count_str = line.strip_prefix("COUNT = ").unwrap().trim();

            i += 1;
            let expected_md = if i < lines.len() && lines[i].trim().starts_with("MD = ") {
                lines[i].trim().strip_prefix("MD = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            let mut md = current_mc_md.clone();
            for _ in 0..1000 {
                // 루프 내부에서도 동적 해셔 사용
                let mut hasher = DynamicHasher::new(algo_str);
                hasher.update(&md);
                md = hasher.finalize();
            }

            current_mc_md = md.clone();

            let computed_md = hex::encode(&md).to_uppercase();
            output_lines.push(format!("MD = {}", computed_md));

            if !expected_md.is_empty() {
                total += 1;
                if computed_md == expected_md {
                    passed += 1;
                } else {
                    eprintln!("FAIL  Monte Carlo COUNT = {}", count_str);
                    eprintln!("   Expected: {}", expected_md);
                    eprintln!("   Computed: {}", computed_md);
                }
            }
        } else {
            output_lines.push(lines[i].clone());
        }
        i += 1;
    }

    println!("\n=== CAVP 검증 결과 ===");
    println!("총 테스트 케이스 : {}", total);
    println!("PASS           : {}", passed);
    println!("FAIL           : {}", total - passed);

    if let Some(out_path) = output_path {
        let mut f = File::create(out_path)?;
        for line in &output_lines {
            writeln!(f, "{}", line)?;
        }
        println!("응답 파일 생성: {}", out_path);
    }

    if total > 0 && total == passed {
        println!("\n모든 Bit-Oriented 및 Monte Carlo KAT 통과 (SHA3-{})", algo_str);
    } else {
        println!("\n검증 실패에 따른 해시 처리 로직 및 입력 데이터 재확인 필요");
    }

    Ok(())
}