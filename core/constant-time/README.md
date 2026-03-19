# 상수-시간 크레이트 (entlib-native-constant-time)

> Q. T. Felix (수정: 25.03.19 UTC+9)
>
> [English README](README_EN.md)

`entlib-native-constant-time`은 암호학적 구현에서 발생하는 타이밍 부채널 공격(Timing Side-Channel Attack)을 원천적으로 차단하기 위해 설계된 `no_std` 호환 크레이트입니다. 본 크레이트는 비밀 데이터에 의존하는 모든 조건 분기(Conditional Branch)를 제거하고, 연산 소요 시간이 입력 값의 비밀성과 완전히 독립적임을 보장하는 상수-시간(Constant-Time) 프리미티브(Primitive)를 제공합니다.

## 보안 위협 모델

현대 고성능 프로세서는 분기 예측기(Branch Predictor), 투기적 실행(Speculative Execution), 데이터 의존적 파이프라인 지연 등 다양한 마이크로아키텍처 최적화 기법을 활용합니다. 비밀 값을 피연산자로 하는 `if`/`else` 분기문 또는 조건부 반환(Early Return)이 존재할 경우, 공격자는 정밀한 시간 측정만으로 해당 비밀 값을 통계적으로 복원할 수 있습니다. 본 크레이트는 이 공격 표면을 완전히 제거하는 것을 목표로 합니다.

## 핵심 추상화: Choice 구조체

`Choice` 구조체는 암호학적 조건부 연산의 결과를 안전하게 표현하는 불투명(Opaque) 타입입니다. 내부적으로 `0x00`(거짓) 또는 `0xFF`(참) 두 상태 중 하나만을 가지도록 설계되었으며, 이 불변 조건(Invariant)이 유지되는 한 비트 연산(`&`, `|`, `^`, `!`)은 논리 연산과 수학적으로 동치이면서도 분기를 유발하지 않습니다.

```rust
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Choice(u8); // 0x00 또는 0xFF만 허용
```

내부 필드를 비공개로 유지함으로써 임의의 바이트 값이 `Choice`로 직접 주입되는 것을 방지합니다. 외부에서는 반드시 `from_mask_normalized` 함수를 통해서만 `Choice`를 생성할 수 있으며, 이 함수는 임의의 `u8` 입력을 `0x00` 또는 `0xFF`로 정규화합니다.

> [!NOTE]
> **정규화 메커니즘**: 임의의 마스크 값 $m \in [0, 255]$에 대하여 정규화 과정은 다음과 같이 전개됩니다.
> 
> 먼저 $m' = m \mathbin{|} (-m)$을 산출하면, $m = 0$일 때 $m' = 0$, $m \ne 0$일 때 $m'$의 최상위 비트(MSB)는 반드시 1이 됩니다.
> 
> 이후 $b = m' \gg 7$로 MSB를 추출하면 $b \in \{0, 1\}$이 확정되고, 최종 마스크 $c = -b$ (2의 보수)는 $b = 0$이면 `0x00`, $b = 1$이면 `0xFF`를 산출합니다.
> 
> 이 일련의 과정은 단 세 개의 비분기 CPU 명령어로 컴파일됩니다.

`unwrap_u8` 메서드는 컴파일러 최적화가 내부 값을 상수로 접어(Constant Folding) 분기를 유발하는 것을 방지하기 위해 `core::hint::black_box`를 경유하여 반환합니다.

## 트레이트 명세

### `ConstantTimeEq`

두 값의 동일성 여부를 상수-시간으로 판별합니다. `ct_eq` 함수는 `Choice(0xFF)`(동일), `ct_ne`는 `Choice(0xFF)`(상이)를 반환하며, `ct_is_ge`는 대소 관계를 판별합니다.

> [!NOTE]
> **동일성 판별 (`ct_eq`)**: 두 부호 없는 정수 $a, b$에 대하여 $v = a \oplus b$를 산출합니다.
>
> $a = b$이면 $v = 0$이고 $v \mathbin{|} (-v) = 0$이므로 MSB는 0입니다.
> 
> $a \ne b$이면 $v \ne 0$이고 $v \mathbin{|} (-v)$의 MSB는 반드시 1입니다.
> 
> MSB를 추출한 뒤 $\mathtt{mask} = -((\text{msb} \oplus 1))$로 최종 마스크를 산출합니다.
> 
> $a = b$이면 `0xFF`, $a \ne b$이면 `0x00`이 반환됩니다.

```rust
let v = *self ^ *other;
let msb = (v | v.wrapping_neg()) >> (u64::BITS - 1);
let mask = ((msb as u8) ^ 1).wrapping_neg(); // 0x00 또는 0xFF
```

> [!NOTE]
> **대소 판별 (`ct_is_ge`)**: 부호 없는 정수의 $a \ge b$ 판별은 뺄셈 $a - b$에서 언더플로우(Borrow) 발생 여부로 환원됩니다.
> 
> Borrow 방정식 $\text{borrow} = (\lnot a \land b) \mathbin{|} (\lnot(a \oplus b) \land (a - b))$에서 결과의 MSB가 1이면 $a < b$, 0이면 $a \ge b$입니다.
> 
> 이 공식은 정수 폭에 무관하게 올바르게 동작하도록 타입 크기 `<$t>::BITS`를 동적으로 참조합니다.

부호 있는 정수의 동일성 판별 시에는 산술 시프트(Arithmetic Shift)로 인한 MSB 오염을 회피하기 위해 부호 없는 정수로 재해석(bitwise reinterpretation)한 뒤 기존 로직으로 위임합니다. 대소 비교 시에는 2의 보수 표현에서 부호 비트를 XOR로 반전시켜 ($a' = a_u \oplus 2^{N-1}$) 수학적 대소 순서를 보존한 채 부호 없는 정수 도메인으로 안전하게 사상(Mapping)합니다.

### `ConstantTimeSelect`

`ct_select(a, b, choice)`는 `choice`가 `0xFF`이면 `a`를, `0x00`이면 `b`를 반환합니다. Sign-Extension 트릭을 활용하여 `choice` 내부의 `u8`을 `i8`로 재해석한 뒤 대상 타입으로 부호 확장(Sign-Extend)합니다. `0xFF as i8`은 $-1$이며, 이를 임의의 정수형으로 확장하면 모든 비트가 1인 마스크가 됩니다. 이를 통해 분기 없이 비트 단위 다중화(Bitwise Multiplexing)를 수행합니다.

$$\text{result} = (a \land \text{mask}) \mathbin{|} (b \land \lnot\text{mask})$$

```rust
let mask = (choice.unwrap_u8() as i8) as T;
(a & mask) | (b & !mask)
```

### `ConstantTimeSwap`

`ct_swap(a, b, choice)`는 `choice`가 `0xFF`일 때 `a`와 `b`의 값을 교환하고, `0x00`일 때 원래 값을 유지합니다. XOR 스왑 알고리즘을 조건 마스크와 결합하여 추가 임시 버퍼 없이 분기 없는 교환을 구현합니다.

$$t = (a \oplus b) \land \text{mask}, \quad a' = a \oplus t, \quad b' = b \oplus t$$

이 기법은 타원 곡선 스칼라 곱셈(ECSM)의 몽고메리 래더(Montgomery Ladder)와 같이 비밀 비트에 의한 조건부 교환이 빈번히 요구되는 암호 알고리즘에서 필수적으로 활용됩니다.

### `ConstantTimeIsZero` 및 `ConstantTimeIsNegative`

`ct_is_zero`는 값이 0인지를 판별하며, 기존 `ct_eq` 구현에 위임하여 중복 로직을 배제합니다. `ct_is_negative`는 MSB를 논리 시프트(Logical Shift)로 추출하여 판별합니다. 부호 있는 정수의 경우 산술 시프트로 인한 마스크 오염을 방지하기 위해 반드시 부호 없는 정수로 변환한 후 시프트를 수행합니다.

$$\text{mask} = -\left(\left(\text{val}_u \gg (N-1)\right) \land 1\right)$$

이 연산은 단일 `SHR` 명령어와 단일 `NEG` 명령어만으로 컴파일됩니다. `ct_is_negative`는 다중 정밀도(Multi-Precision) 산술에서 `wrapping_sub`의 언더플로우를 분기 없이 감지하거나, 모듈러 보정(Modular Reduction)의 필요 여부를 판단하는 데 활용됩니다.

## 적용 범위

본 크레이트의 모든 트레이트는 Rust 표준 정수 타입 `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, `i8`, `i16`, `i32`, `i64`, `i128`, `isize`에 대해 선언적 매크로를 통해 일괄 구현됩니다. 각 구현체는 `#[inline(always)]` 어노테이션이 적용되어 호출 오버헤드가 존재하지 않습니다.

## 감사 인프라

### `audit_mode` 피처: 어셈블리 검사 지원

`audit_mode` 피처를 활성화하면 `wrapper` 모듈이 컴파일됩니다. 이 모듈은 `#[inline(never)]` 및 `#[unsafe(no_mangle)]` 어노테이션이 적용된 감사 전용 함수들을 노출하며, 컴파일러가 해당 함수를 인라인하거나 심볼을 맹글링하지 않도록 강제합니다. 이로써 `objdump` 또는 `llvm-objdump`로 생성된 어셈블리를 직접 검사하여 의도치 않은 분기 명령어(`jne`, `je`, `cmov` 등)가 삽입되었는지 확인할 수 있습니다.

```bash
cargo build --release -p entlib-native-constant-time --features audit_mode
objdump -d target/release/libentlib_native_constant_time.rlib | grep -E 'j[a-z]+'
```

### `valgrind_taint_audit` 피처: Memcheck 기반 오염 추적

`valgrind_taint_audit` 피처는 Valgrind의 Memcheck 도구와 연동되는 오염 추적(Taint Tracking) 테스트를 활성화합니다. 테스트는 Valgrind Client Request 인터페이스(`VALGRIND_MAKE_MEM_UNDEFINED`)를 통해 비밀 데이터를 오염(Taint) 상태로 표시하고, 연산 완료 후 결과 메모리가 오염 상태를 전파하는지 검사합니다. Valgrind의 추상 해석(Abstract Interpretation)은 오염된 값에 의존하는 분기(`jcc` 명령어)를 탐지하면 오류를 보고합니다. 이 테스트는 Linux `x86_64` 환경에서만 유효하며, Valgrind가 존재하지 않는 환경에서는 요청이 무시되어 테스트가 정상 통과합니다.

```bash
cargo test -p entlib-native-constant-time \
    --features valgrind_taint_audit \
    --target x86_64-unknown-linux-gnu -- --test-threads=1
# valgrind --tool=memcheck --track-origins=yes <binary>
```

> [!WARNING]
> 이 테스트는 현재 정상적으로 수행되지 않을 수 있습니다. 저희는 이 테스트가 엄밀하며, 정합한지에 대한 판단 중에 있습니다. 만약 이 테스트에 의견이 있으시다면 [적극적으로 피드백 해주시길 바랍니다.](../../CONTRIBUTION.md)

### DudeCT 통계적 타이밍 검증

`dudect_audit` 벤치마크는 DudeCT 방법론에 기반하여 통계적 타이밍 동등성(Statistical Timing Equivalence)을 검증합니다. Welch's t-검정(test)을 적용하여 비밀 값이 동일한 경우(`Class::Right`)와 상이한 경우(`Class::Left`) 각 100,000회 이상의 실행 시간 분포를 비교합니다. $|t| < 5$ 기준을 충족하면 두 집단 간의 타이밍 차이가 통계적으로 유의하지 않다고 판단합니다.

> [!IMPORTANT]
> 본 벤치마크는 가상화 환경(VM, 퍼블릭 클라우드)에서 하이퍼바이저 개입 및 CPU 클럭 변동으로 인해 t 값이 오염될 수 있습니다. 신뢰할 수 있는 결과를 얻기 위해서는 BIOS/UEFI 수준에서 전원 관리 기능(Turbo Boost, C-states)을 비활성화하고 CPU 주파수를 고정한 베어메탈 환경에서 실행할 것을 권고합니다.

```bash
cargo +nightly build --release -p entlib-native-constant-time --bench dudect_audit
./target/release/deps/dudect_audit-<hash>
```

## 설계 원칙 요약

본 크레이트는 세 가지 수준의 보안 검증 체계를 순차적으로 적용하는 방어 심층화(Defense-in-Depth) 전략을 채택합니다. 

1. 구현 수준에서 XOR/OR/NEG 등 단일 명령어 비트 연산만을 사용하여 분기의 발생 가능성을 원천 차단합니다.
2. 어셈블리 감사(`audit_mode`)를 통해 컴파일러 최적화가 예상치 않은 분기를 삽입하지 않았음을 어셈블리 수준에서 검증합니다.
3. DudeCT 통계 검증 및 Valgrind 오염 추적을 통해 최종 바이너리가 실제 환경에서 타이밍 독립성을 유지함을 확인합니다.