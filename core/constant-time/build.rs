use std::env;

fn main() {
    // valgrind_audit 플래그가 활성화된 경우에만 C Shim 코드를 컴파일해서 메인 빌드 오염 방지
    let is_audit_enabled = env::var("CARGO_FEATURE_VALGRIND_AUDIT").is_ok();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if is_audit_enabled && target_os == "linux" {
        println!("cargo:rerun-if-changed=tests/taint_shim.c");

        cc::Build::new()
            .file("tests/taint_shim.c")
            // 최적화 억제 유지 (Valgrind 매크로 소실 방지)
            .opt_level(0)
            .compile("taint_shim");

        println!("cargo:rustc-link-lib=static=taint_shim");
    }
}
