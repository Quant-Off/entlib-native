//! 얽힘 라이브러리(EntanglementLib) entlib-native 네이티브 SHAKE128 / SHAKE256 XOF Bit-Oriented & Monte Carlo CAVP 검증 도구
//! ShortMsg, LongMsg, VariableOut, Monte 카를로 테스트 완벽 지원
//!
//! nist sha3vs 및 acvp 규격에 따르면
//! - 다음 루프의 입력 메시지(MSG[i])는 항상 이전 출력(MD[i-1])의 가장 왼쪽 128비트(16바이트)를 사용해야 함
//! - 만약 이전 출력의 길이가 128비트보다 짧을 경우, 128비트가 될 때까지 오른쪽 끝에 0을 채워 넣음

use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};

use entlib_native_sha3::api::{SHAKE128, SHAKE256};

enum DynamicShakeHasher {
    Shake128(SHAKE128),
    Shake256(SHAKE256),
}

impl DynamicShakeHasher {
    fn new(algo: &str) -> Self {
        match algo.to_uppercase().as_str() {
            "SHAKE128" | "128" => DynamicShakeHasher::Shake128(SHAKE128::new()),
            "SHAKE256" | "256" => DynamicShakeHasher::Shake256(SHAKE256::new()),
            _ => panic!("지원하지 않는 알고리즘입니다. (SHAKE128, SHAKE256 중 택일): {}", algo),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            DynamicShakeHasher::Shake128(h) => h.update(data),
            DynamicShakeHasher::Shake256(h) => h.update(data),
        }
    }

    fn finalize(self, output_len: usize) -> Vec<u8> {
        match self {
            DynamicShakeHasher::Shake128(h) => h.finalize(output_len),
            DynamicShakeHasher::Shake256(h) => h.finalize(output_len),
        }
    }

    fn finalize_bits(self, output_len: usize, last_byte: u8, valid_bits: usize) -> Vec<u8> {
        match self {
            DynamicShakeHasher::Shake128(h) => h.finalize_bits(output_len, last_byte, valid_bits),
            DynamicShakeHasher::Shake256(h) => h.finalize_bits(output_len, last_byte, valid_bits),
        }
    }
}

/// 단일 SHAKE 연산을 수행하고 Bit-Oriented 입출력 LSB 마스킹을 적용하는 헬퍼 함수
fn compute_shake(algo: &str, msg_data_full: &[u8], in_len_bits: usize, out_len_bits: usize) -> String {
    let mut hasher = DynamicShakeHasher::new(algo);
    let in_rem = in_len_bits % 8;
    let out_byte_len = (out_len_bits + 7) / 8;

    let digest = if in_len_bits == 0 {
        hasher.finalize(out_byte_len)
    } else if in_rem == 0 {
        let in_byte_len = in_len_bits / 8;
        let data = &msg_data_full[0..in_byte_len];
        hasher.update(data);
        hasher.finalize(out_byte_len)
    } else {
        let in_byte_len = (in_len_bits + 7) / 8;
        let mut data = msg_data_full[0..in_byte_len].to_vec();
        data[in_byte_len - 1] &= (1u8 << in_rem) - 1;

        let complete_bytes = &data[..in_byte_len - 1];
        hasher.update(complete_bytes);
        let last_byte = data[in_byte_len - 1];
        hasher.finalize_bits(out_byte_len, last_byte, in_rem)
    };

    let mut digest_masked = digest;
    let out_rem = out_len_bits % 8;
    if out_rem != 0 && !digest_masked.is_empty() {
        let last_idx = digest_masked.len() - 1;
        digest_masked[last_idx] &= (1u8 << out_rem) - 1;
    }

    hex::encode(&digest_masked).to_uppercase()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("사용법: {} <SHAKE128|SHAKE256> <ShortMsg.rsp | Monte.rsp | VariableOut.rsp> [output.rsp]", args[0]);
        std::process::exit(1);
    }

    let algo_str = &args[1];
    let input_path = &args[2];
    let output_path = args.get(3);

    println!("[NIST FIPS 202] {} Bit-Oriented XOF CAVP 검증 시작", algo_str);

    let file = File::open(input_path)?;
    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let mut output_lines = Vec::new();
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut i = 0;

    let mut global_output_len: Option<usize> = None;
    let mut global_input_len: Option<usize> = None;
    let mut global_min_out_bytes: Option<usize> = None;
    let mut global_max_out_bytes: Option<usize> = None;

    let mut monte_msg: Vec<u8> = Vec::new();
    let mut current_mc_md: Vec<u8> = Vec::new();
    let mut current_out_len_bytes: usize = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with("[Outputlen =") {
            output_lines.push(lines[i].clone());
            let val_str = line.split('=').nth(1).unwrap().strip_suffix("]").unwrap().trim();
            global_output_len = Some(val_str.parse().unwrap());
        } else if line.starts_with("[Input Length =") {
            output_lines.push(lines[i].clone());
            let val_str = line.split('=').nth(1).unwrap().strip_suffix("]").unwrap().trim();
            global_input_len = Some(val_str.parse().unwrap());
        } else if line.starts_with("[Minimum Output Length") {
            output_lines.push(lines[i].clone());
            let val_str = line.split('=').nth(1).unwrap().strip_suffix("]").unwrap().trim();
            global_min_out_bytes = Some(val_str.parse::<usize>().unwrap() / 8);
        } else if line.starts_with("[Maximum Output Length") {
            output_lines.push(lines[i].clone());
            let val_str = line.split('=').nth(1).unwrap().strip_suffix("]").unwrap().trim();
            global_max_out_bytes = Some(val_str.parse::<usize>().unwrap() / 8);
        } else if line.starts_with("Msg = ") {
            output_lines.push(lines[i].clone());
            let hex_str = line.strip_prefix("Msg = ").unwrap().trim();
            monte_msg = hex::decode(hex_str).expect("Msg hex decode 실패");
        } else if line.starts_with("Len = ") {
            // [1] ShortMsg / LongMsg 블록 처리
            output_lines.push(lines[i].clone());
            let len: usize = line.strip_prefix("Len = ").unwrap().trim().parse().unwrap();

            i += 1;
            let msg_hex = lines[i].trim().strip_prefix("Msg = ").unwrap_or("").trim().to_string();
            output_lines.push(lines[i].clone());

            i += 1;
            let expected_out = if i < lines.len() && lines[i].trim().starts_with("Output = ") {
                lines[i].trim().strip_prefix("Output = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            let out_bits = global_output_len.expect("global [Outputlen =] 가 누락되었습니다.");
            let msg_data = hex::decode(&msg_hex).unwrap_or_default();

            let computed_out = compute_shake(algo_str, &msg_data, len, out_bits);
            output_lines.push(format!("Output = {}", computed_out));

            if !expected_out.is_empty() {
                total += 1;
                if computed_out == expected_out { passed += 1; }
                else { eprintln!("FAIL Short/LongMsg Len = {}", len); }
            }
        } else if line.starts_with("COUNT = ") {
            // [2] VariableOut / Monte 블록 처리
            output_lines.push(lines[i].clone());
            let count: usize = line.strip_prefix("COUNT = ").unwrap().trim().parse().unwrap();

            i += 1;
            output_lines.push(lines[i].clone());
            let out_len_bits_from_file: usize = lines[i].trim().strip_prefix("Outputlen = ").unwrap().trim().parse().unwrap();

            i += 1;
            let mut msg_data = Vec::new();
            let mut is_var_out = false;

            if i < lines.len() && lines[i].trim().starts_with("Msg = ") {
                is_var_out = true;
                msg_data = hex::decode(lines[i].trim().strip_prefix("Msg = ").unwrap().trim()).unwrap();
                output_lines.push(lines[i].clone());
                i += 1;
            }

            let expected_out = if i < lines.len() && lines[i].trim().starts_with("Output = ") {
                lines[i].trim().strip_prefix("Output = ").unwrap().trim().to_uppercase()
            } else {
                i -= 1;
                String::new()
            };

            let computed_out: String;
            if is_var_out {
                // VariableOut 테스트
                let in_len_bits = global_input_len.expect("global [Input Length =] 가 누락되었습니다.");
                computed_out = compute_shake(algo_str, &msg_data, in_len_bits, out_len_bits_from_file);
            } else {
                // Monte Carlo 테스트 (NIST SP 800-185 규격)
                // Q. T. Felix NOTE: 이 코드로 인해 SHAKE256을 테스트할 때 16바이트가 아닌 32바이트를 잘라내어 해시
                //                   입력으로 사용하게 됨. 결국 첫 번째 루프 이후부터 입력값이 스펙과 완전히 달라짐. 그래서 다 실패
                // let target_input_bytes = if algo_str.contains("128") { 16 } else { 32 };
                let target_input_bytes = 16;

                if count == 0 {
                    current_mc_md = monte_msg.clone();
                    current_out_len_bytes = global_max_out_bytes.unwrap();
                }

                let min_out_bytes = global_min_out_bytes.unwrap();
                let max_out_bytes = global_max_out_bytes.unwrap();
                let range = max_out_bytes - min_out_bytes + 1;

                let mut md = current_mc_md.clone();
                let mut out_bytes = current_out_len_bytes;

                for _ in 0..1000 {
                    let mut msg_i = md.clone();
                    // 이전 출력의 leftmost 128(또는 256) bits만 다음 Seed로 사용
                    if msg_i.len() >= target_input_bytes {
                        msg_i.truncate(target_input_bytes);
                    } else {
                        msg_i.resize(target_input_bytes, 0u8);
                    }

                    let digest_hex = compute_shake(algo_str, &msg_i, target_input_bytes * 8, out_bytes * 8);
                    md = hex::decode(&digest_hex).unwrap();

                    // NIST Spec: Rightmost 16 bits of Output_i 추출 및 정수 변환
                    let rightmost_16_val = if md.len() >= 2 {
                        let b1 = md[md.len() - 2] as usize;
                        let b2 = md[md.len() - 1] as usize;
                        (b1 << 8) | b2
                    } else {
                        md[0] as usize
                    };

                    // 다음 루프에서 사용할 동적 Outputlen 업데이트
                    out_bytes = min_out_bytes + (rightmost_16_val % range);
                }

                current_mc_md = md.clone();
                current_out_len_bytes = out_bytes;

                computed_out = hex::encode(&md).to_uppercase();
            }

            output_lines.push(format!("Output = {}", computed_out));

            if !expected_out.is_empty() {
                total += 1;
                if computed_out == expected_out { passed += 1; }
                else { eprintln!("FAIL COUNT = {}", count); }
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
        for line in &output_lines { writeln!(f, "{}", line)?; }
        println!("응답 파일 생성: {}", out_path);
    }

    Ok(())
}