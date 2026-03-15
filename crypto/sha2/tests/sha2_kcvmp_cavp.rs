mod kcmvp_cavp_test {
    use std::fs::File;
    use std::io::{BufRead, BufReader, BufWriter, Write};

    use entlib_native_secure_buffer::SecureBuffer;
    use entlib_native_sha2::api::{SHA224, SHA256, SHA384, SHA512};

    pub trait CavpHash {
        fn new() -> Self;
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> Result<SecureBuffer, &'static str>;
    }

    macro_rules! impl_cavp_hash {
        ($algo:ident) => {
            impl CavpHash for $algo {
                fn new() -> Self {
                    Self::new()
                }
                fn update(&mut self, data: &[u8]) {
                    self.update(data);
                }
                fn finalize(self) -> Result<SecureBuffer, &'static str> {
                    self.finalize()
                }
            }
        };
    }

    impl_cavp_hash!(SHA224);
    impl_cavp_hash!(SHA256);
    impl_cavp_hash!(SHA384);
    impl_cavp_hash!(SHA512);

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.trim();
        if hex.is_empty() {
            return Vec::new();
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    /// SMT / LMT 테스트 프로세서
    pub fn process_smt_lmt<T: CavpHash>(req_path: &str, rsp_path: &str) -> std::io::Result<()> {
        let req_file = File::open(req_path)?;
        let mut rsp_file = BufWriter::new(File::create(rsp_path)?);
        let reader = BufReader::new(req_file);

        let mut current_len: usize = 0;

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();

            if trimmed.starts_with("Len =") {
                current_len = trimmed.replace("Len =", "").trim().parse().unwrap_or(0);
                writeln!(rsp_file, "{}", trimmed)?;
            } else if trimmed.starts_with("Msg =") {
                let msg_hex = trimmed.replace("Msg =", "").trim().to_string();
                let mut msg_bytes = hex_to_bytes(&msg_hex);

                // [수정점] Len 속성은 '비트(Bit) 길이'이므로 바이트 길이로 환산하여 정확히 절삭
                let byte_len = current_len / 8;
                if msg_bytes.len() > byte_len {
                    msg_bytes.truncate(byte_len);
                }

                let mut hasher = T::new();
                hasher.update(&msg_bytes);
                let md_buffer = hasher.finalize().expect("Hash finalization failed");
                let md_hex = bytes_to_hex(md_buffer.as_slice());

                writeln!(rsp_file, "{}", trimmed)?;
                writeln!(rsp_file, "MD = {}", md_hex)?;
                // writeln!(rsp_file)?;
            } else {
                writeln!(rsp_file, "{}", line)?;
            }
        }
        rsp_file.flush()?;
        Ok(())
    }

    /// MCT (Monte Carlo Test) 프로세서
    pub fn process_mct<T: CavpHash>(req_path: &str, rsp_path: &str) -> std::io::Result<()> {
        let req_file = File::open(req_path)?;
        let mut rsp_file = BufWriter::new(File::create(rsp_path)?);
        let reader = BufReader::new(req_file);

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();

            if trimmed.starts_with("Seed =") {
                writeln!(rsp_file, "{}", trimmed)?;
                writeln!(rsp_file)?;

                let seed_hex = trimmed.replace("Seed =", "").trim().to_string();
                let mut current_seed = hex_to_bytes(&seed_hex);

                // 외부 루프 100회: j = 0 to 99
                for count in 0..100 {
                    writeln!(rsp_file, "COUNT = {}", count)?;

                    // 초기화: MD_0 = MD_1 = MD_2 = Seed
                    let mut md_0 = current_seed.clone();
                    let mut md_1 = current_seed.clone();
                    let mut md_2 = current_seed.clone();

                    // 내부 루프 1000회: i = 3 to 1002
                    for _ in 3..1003 {
                        // M_i = MD_{i-3} || MD_{i-2} || MD_{i-1}
                        // 세 개의 이전 해시값을 concatenation
                        let mut m_i = Vec::with_capacity(md_0.len() * 3);
                        m_i.extend_from_slice(&md_0);
                        m_i.extend_from_slice(&md_1);
                        m_i.extend_from_slice(&md_2);

                        // MD_i = SHA2(M_i)
                        let mut hasher = T::new();
                        hasher.update(&m_i);
                        let digest = hasher.finalize().expect("Hash finalization failed");
                        let md_i = digest.as_slice().to_vec();

                        // 윈도우 시프트 (다음 루프를 위해 상태 업데이트)
                        md_0 = md_1;
                        md_1 = md_2;
                        md_2 = md_i;
                    }

                    // 루프 종료 후 출력 및 Seed 업데이트: MD_j = Seed = MD_1002
                    current_seed = md_2.clone();

                    writeln!(rsp_file, "MD = {}", bytes_to_hex(&current_seed))?;
                    writeln!(rsp_file)?;
                }
            } else {
                writeln!(rsp_file, "{}", line)?;
            }
        }
        rsp_file.flush()?;
        Ok(())
    }

    //
    // 실제 테스트 실행부
    //
    #[test]
    fn cavp_sha2_test() {
        let dir = match std::env::var("KCMVP_CAVP_DIR") {
            Ok(val) => val,
            Err(_) => panic!("env"),
        };

        // 공통 경로 추출로 가독성 및 유지보수성 향상
        let base_path = format!("{}/entanglementlib__CAVP_3_20260313003528", dir);

        // SHA-224
        process_smt_lmt::<SHA224>(
            &format!("{}/SHA2-224_(Byte)_SMT.req", base_path),
            &format!("{}/SHA2-224_(Byte)_SMT.rsp", base_path),
        )
        .unwrap();
        process_smt_lmt::<SHA224>(
            &format!("{}/SHA2-224_(Byte)_LMT.req", base_path),
            &format!("{}/SHA2-224_(Byte)_LMT.rsp", base_path),
        )
        .unwrap();
        process_mct::<SHA224>(
            &format!("{}/SHA2-224_(Byte)_MCT.req", base_path),
            &format!("{}/SHA2-224_(Byte)_MCT.rsp", base_path),
        )
        .unwrap();

        // SHA-256
        process_smt_lmt::<SHA256>(
            &format!("{}/SHA2-256_(Byte)_SMT.req", base_path),
            &format!("{}/SHA2-256_(Byte)_SMT.rsp", base_path),
        )
        .unwrap();
        process_smt_lmt::<SHA256>(
            &format!("{}/SHA2-256_(Byte)_LMT.req", base_path),
            &format!("{}/SHA2-256_(Byte)_LMT.rsp", base_path),
        )
        .unwrap();
        process_mct::<SHA256>(
            &format!("{}/SHA2-256_(Byte)_MCT.req", base_path),
            &format!("{}/SHA2-256_(Byte)_MCT.rsp", base_path),
        )
        .unwrap();

        // SHA-384
        process_smt_lmt::<SHA384>(
            &format!("{}/SHA2-384_(Byte)_SMT.req", base_path),
            &format!("{}/SHA2-384_(Byte)_SMT.rsp", base_path),
        )
        .unwrap();
        process_smt_lmt::<SHA384>(
            &format!("{}/SHA2-384_(Byte)_LMT.req", base_path),
            &format!("{}/SHA2-384_(Byte)_LMT.rsp", base_path),
        )
        .unwrap();
        process_mct::<SHA384>(
            &format!("{}/SHA2-384_(Byte)_MCT.req", base_path),
            &format!("{}/SHA2-384_(Byte)_MCT.rsp", base_path),
        )
        .unwrap();

        // SHA-512
        process_smt_lmt::<SHA512>(
            &format!("{}/SHA2-512_(Byte)_SMT.req", base_path),
            &format!("{}/SHA2-512_(Byte)_SMT.rsp", base_path),
        )
        .unwrap();
        process_smt_lmt::<SHA512>(
            &format!("{}/SHA2-512_(Byte)_LMT.req", base_path),
            &format!("{}/SHA2-512_(Byte)_LMT.rsp", base_path),
        )
        .unwrap();
        process_mct::<SHA512>(
            &format!("{}/SHA2-512_(Byte)_MCT.req", base_path),
            &format!("{}/SHA2-512_(Byte)_MCT.rsp", base_path),
        )
        .unwrap();
    }
}
