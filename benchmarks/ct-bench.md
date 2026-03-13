# Constant-Time Benchmark

> [이 벤치마킹은 어떻게 수행되나요?](README.md)

## DudeCT 벤치마킹

이 벤치마킹은 다음과 같이 수행할 수 있습니다.

```bash
# 빌드
$ cargo +nightly build --release -p entlib-native-constant-time --bench dudect_audit

# 실행
$ ./target/release/deps/dudect_audit-...
```