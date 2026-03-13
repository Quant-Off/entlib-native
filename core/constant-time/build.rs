use std::env;

fn main() {
    // Q. T. Felix NOTE: 구글링해보니 Valgrind 기반 오염 추적은 Linux 환경에서 가장 높은 신뢰도를 보장한다고 함
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "linux" {
        // C Shim 코드 파일의 변경 사항을 추적하여 불필요한 재빌드 방지
        println!("cargo:rerun-if-changed=tests/taint_shim.c");

        // cc 크레이트를 사용하여 시스템의 C 컴파일러(GCC/Clang)로 정적 라이브러리 빌드
        cc::Build::new()
            .file("tests/taint_shim.c")
            // C 컴파일러 최적화로 인한 Valgrind 매크로 소실 방지를 위해 최적화 억제 권장
            .opt_level(0)
            .compile("taint_shim");

        // 생성된 정적 라이브러리(libtaint_shim.a)를 Rust 테스트 바이너리에 안전하게 링킹
        println!("cargo:rustc-link-lib=static=taint_shim");
    }
}