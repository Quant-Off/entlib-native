#[cfg(test)]
mod tests {
    /// FIPS 204 (ML-DSA) 모듈러스
    const Q: i64 = 8380417;

    /// Q에 대한 512차 원시 단위근
    const ZETA: i64 = 1753;

    /// 몽고메리 변환 상수 R = 2^32 mod Q
    const R: i64 = (1i64 << 32) % Q;

    /// 8비트 정수의 비트 반전 (Bit Reversal)
    fn bit_reverse(mut n: u8) -> u8 {
        let mut res = 0;
        for _ in 0..8 {
            res = (res << 1) | (n & 1);
            n >>= 1;
        }
        res
    }

    /// 모듈러 거듭제곱 (Base^Exp mod Q)
    fn mod_pow(mut base: i64, mut exp: i64) -> i64 {
        let mut res = 1;
        base %= Q;
        while exp > 0 {
            if exp % 2 == 1 {
                res = (res * base) % Q;
            }
            base = (base * base) % Q;
            exp /= 2;
        }
        res
    }

    /// 모듈러 역원 계산 (Fermat's Little Theorem: a^(Q-2) mod Q)
    fn mod_inv(n: i64) -> i64 {
        mod_pow(n, Q - 2)
    }

    #[test]
    fn generate_ntt_constants() {
        println!("// === ZETAS 생성 결과 ===");
        println!("pub const ZETAS: [Fq; 256] = [");
        for i in 0..256 {
            // 인덱스를 8비트 반전
            let brv = bit_reverse(i as u8) as i64;

            // zeta^brv mod Q
            let z = mod_pow(ZETA, brv);

            // 몽고메리 도메인으로 변환: (z * R) mod Q
            let z_mont = (z * R) % Q;

            println!("    Fq::new({}), // ZETAS[{}]", z_mont, i);
        }
        println!("];\n");

        println!("// === INTT_ZETAS 생성 결과 ===");
        println!("pub const INTT_ZETAS: [Fq; 256] = [");

        // INTT는 음수 지수(-brv)를 사용하므로, ZETA의 역원을 구합니다.
        let zeta_inv = mod_inv(ZETA);

        for i in 0..256 {
            let brv = bit_reverse(i as u8) as i64;

            // (zeta^-1)^brv mod Q
            let z_inv = mod_pow(zeta_inv, brv);

            // 몽고메리 도메인으로 변환
            let z_inv_mont = (z_inv * R) % Q;

            println!("    Fq::new({}), // INTT_ZETAS[{}]", z_inv_mont, i);
        }
        println!("];");

        // INV_N_MONT 검증 (256^-1 * 2^32 mod Q)
        let n_inv = mod_inv(256);
        let n_inv_mont = (n_inv * R) % Q;
        println!("\n// === INV_N_MONT ===");
        println!("pub const INV_N_MONT: Fq = Fq::new({});", n_inv_mont);
    }
}
