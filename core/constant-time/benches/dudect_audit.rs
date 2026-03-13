//! TODO: 베어메탈에서 실행되야 할 벤치마킹입니다. 구글링해보니 퍼블릭 클라우드 인프라 서비스는
//!       VM에 노이즈와 하이퍼바이저 개입으로 인해 t-test 값이 오염된다고 합니다.
//!       운영체제 전원 관리 및 CPU 클럭 변동 기술을 BIOS/UEFI 수준에서 비활성화하거나,
//!       OS에서 주파수를 고정해야 한다고 하네요... 잘은 모르겠습니다.
//!
//! DudeCT 벤치마크는 최적화 방지 및 런타임 벤치마킹 기능 활용을 위해 nightly 툴체인이 권장됩니다.
//! 다음과 같이 빌드 후 바이너리를 실행하여 벤치마킹 할 수 있습니다.
//! ```bash
//! # 빌드
//! $ cargo +nightly build --release -p entlib-native-newer-constant-time --bench dudect_audit
//!
//! # 실행
//! $ ./target/release/deps/dudect_audit-...
//! ```

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use dudect_bencher::rand::Rng;
use entlib_native_newer_constant_time::traits::{ConstantTimeEq, ConstantTimeSelect};
use entlib_native_newer_constant_time::choice::Choice;

/// [ConstantTimeEq::ct_eq] 검증
/// 두 값이 완벽히 동일한 경우([Class::Right])와 서로 다른 경우([Class::Left])의
/// 연산 소요 시간 분포를 교차 검증합니다.
fn bench_ct_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = vec![(0u64, 0u64); 100_000];
    let mut classes = vec![Class::Right; 100_000];

    for (input, class) in inputs.iter_mut().zip(classes.iter_mut()) {
        let a: u64 = rng.r#gen();
        let b: u64 = rng.r#gen();

        // 50% 확률로 동일한 값 쌍과 다른 값 쌍을 생성
        if rng.r#gen::<bool>() {
            *input = (a, a);
            *class = Class::Right; // 일치 상태
        } else {
            *input = (a, b);
            *class = Class::Left; // 불일치 상태
        }
    }

    for (class, (a, b)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            // black_box를 통해 컴파일러 DCE 최적화 억제
            let _ = core::hint::black_box(
                core::hint::black_box(a).ct_eq(core::hint::black_box(&b))
            );
        });
    }
}

/// [ConstantTimeSelect::ct_select] 검증
/// 조건 마스크가 0xFF(True)인 경우([Class::Right])와 0x00(False)인 경우([Class::Left])
/// 데이터 선택 과정에서 타이밍 차이가 발생하는지 검증합니다.
fn bench_ct_select(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = vec![(0u64, 0u64, 0u8); 100_000];
    let mut classes = vec![Class::Right; 100_000];

    for (input, class) in inputs.iter_mut().zip(classes.iter_mut()) {
        let a: u64 = rng.r#gen();
        let b: u64 = rng.r#gen();

        if rng.r#gen::<bool>() {
            *input = (a, b, 0xFF);
            *class = Class::Right; // True 분기
        } else {
            *input = (a, b, 0x00);
            *class = Class::Left;  // False 분기
        }
    }

    for (class, (a, b, mask)) in classes.into_iter().zip(inputs.into_iter()) {
        // Choice 구조체의 내부 필드는 private이라서 벤치마크 환경에 한하여
        // 메모리 transmute를 통해 강제로 마스크 값 주입
        let choice = unsafe { core::mem::transmute::<u8, Choice>(mask) };

        runner.run_one(class, || {
            let _ = core::hint::black_box(u64::ct_select(
                core::hint::black_box(&a),
                core::hint::black_box(&b),
                core::hint::black_box(choice),
            ));
        });
    }
}

// todo: 더

ctbench_main!(bench_ct_eq, bench_ct_select);