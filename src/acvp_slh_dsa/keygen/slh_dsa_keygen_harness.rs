use crate::acvp_slh_dsa::common::{Request, Response};
use crate::acvp_slh_dsa::keygen::slh_dsa_keygen::{
    slh_keygen_internal_with_params, SlhPrivateKey, SlhPublicKey,
};
use crate::acvp_slh_dsa::keygen::slh_dsa_keygen_serde::{
    SLHDSAKEYGENERTestGroup, SLHDSAKEYGENResponseTestCase, SLHDSAKEYGENResponseTestGroup,
    SLHDSAKEYGENTestGroup,
};
use crate::acvp_slh_dsa::slh_dsa_params::get_params_by_name;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;

fn main() -> Result<(), Box<dyn Error>> {
    println!("SLH-DSA KeyGen ACVP Test Harness");

    // 필요한 json 파일 로드
    let acvp_dir = env::var("ACVP_DIR")?;

    let keygen_prompt = File::open(acvp_dir.clone() + "/keygen_prompt.json")?;
    let keygen_prompt_reader = BufReader::new(keygen_prompt);
    let keygen_expected_results_file = File::open(acvp_dir + "/keygen_expectedResults.json")?;
    let keygen_expected_results_reader = BufReader::new(keygen_expected_results_file);

    // json 역직렬화 (deserialize)
    let prompt: Request<SLHDSAKEYGENTestGroup> = serde_json::from_reader(keygen_prompt_reader)?;
    let expected_results: Request<SLHDSAKEYGENERTestGroup> =
        serde_json::from_reader(keygen_expected_results_reader)?;

    println!(
        "Processing vector set id: prompt '{}', expectedResults '{}'",
        prompt.vs_id, expected_results.vs_id
    );

    // 결과 데이터를 담을 벡터 초기화
    let mut response_groups: Vec<SLHDSAKEYGENResponseTestGroup> = Vec::new();
    let mut total_match = 0;
    let mut total_mismatch = 0;

    // 테스트 그룹 색인
    for (group, expected_group) in prompt
        .test_groups
        .iter()
        .zip(expected_results.test_groups.iter())
    {
        let mut response_tests = Vec::new();

        // 파라미터 세트 선택
        let params = match get_params_by_name(&group.parameter_set) {
            Some(p) => p,
            None => {
                println!(
                    "WARNING: Unknown parameter set '{}', skipping group {}",
                    group.parameter_set, group.tg_id
                );
                continue;
            }
        };

        // 빠른모드
        // if params.h_prime > 5 {
        //     println!("\nSkipping slow Group {}: {} (h'={})", group.tg_id, group.parameter_set, params.h_prime);
        //     continue;
        // }

        println!(
            "\nGroup {}: {} (n={})",
            group.tg_id, group.parameter_set, params.n
        );

        // 테스트 케이스 순회
        for (tc, expected_tc) in group.tests.iter().zip(expected_group.tests.iter()) {
            // 동적 크기 변환
            let sk_seed = hex::decode(&tc.sk_seed)?;
            let sk_prf = hex::decode(&tc.sk_prf)?;
            let pk_seed = hex::decode(&tc.pk_seed)?;

            // 크기 검증
            if sk_seed.len() != params.n || sk_prf.len() != params.n || pk_seed.len() != params.n {
                println!(
                    "  tcId {}: Size mismatch - expected n={}, got sk_seed={}, sk_prf={}, pk_seed={}",
                    tc.tc_id,
                    params.n,
                    sk_seed.len(),
                    sk_prf.len(),
                    pk_seed.len()
                );
                continue;
            }

            let pair: (SlhPrivateKey, SlhPublicKey) =
                slh_keygen_internal_with_params(params, sk_seed, sk_prf, pk_seed);

            let sku8 = hex::encode(pair.0.to_bytes()).to_uppercase();
            let pku8 = hex::encode(pair.1.to_bytes()).to_uppercase();

            // 검증
            let sk_match = sku8 == expected_tc.sk;
            let pk_match = pku8 == expected_tc.pk;

            if !sk_match {
                println!("  Mismatch SK tcId {}", tc.tc_id);
                println!("    expected: {}", expected_tc.sk);
                println!("    got     : {}", sku8);
            } else {
                println!("  Match SK! tcID {}", tc.tc_id);
            }
            if !pk_match {
                println!("  Mismatch PK tcId {}", tc.tc_id);
                println!("    expected: {}", expected_tc.pk);
                println!("    got     : {}", pku8);
            } else {
                println!("  Match PK! tcID {}", tc.tc_id);
            }

            if sk_match && pk_match {
                total_match += 1;
            } else {
                total_mismatch += 1;
            }

            response_tests.push(SLHDSAKEYGENResponseTestCase {
                tc_id: tc.tc_id,
                sk: sku8,
                pk: pku8,
            });
        }

        response_groups.push(SLHDSAKEYGENResponseTestGroup {
            tg_id: group.tg_id,
            tests: response_tests,
        });
    }

    // 최종 응답 생성
    let response = Response {
        vs_id: prompt.vs_id,
        algorithm: prompt.algorithm.clone(),
        mode: prompt.mode.clone(),
        revision: prompt.revision.clone(),
        is_sample: prompt.is_sample,
        test_groups: response_groups,
    };

    // 결과를 json 파일로 저장
    let output_file = File::create("keygen_response.json")?;
    serde_json::to_writer_pretty(output_file, &response)?;

    println!("\n=== Summary ===");
    println!("Total Match: {}", total_match);
    println!("Total Mismatch: {}", total_mismatch);
    println!("Generation complete. Check keygen_response.json");

    Ok(())
}

/// 검증완료!
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        main().unwrap();
    }
}
