# 상수-시간(constant-time) 연산 모듈

이 문서는 [상수-시간 연산 모듈](src/constant_time.rs)에 대해 설명합니다.

## 개요

`constant_time.rs` 모듈은 암호학적 구현에서 필수적인 **상수 시간(Constant-Time)** 연산을 지원하기 위해 설계되었습니다. 이 모듈은 민감한 데이터(예: 비밀키, 난수 등)를 처리할 때,
데이터의 값에 따라 연산 시간이 달라지는 **타이밍 공격(timing attack)** 및 부채널 공격(side-channel attack)을 방지하는 것을 목적으로 합니다.

이 모듈의 핵심 원칙은 CPU의 **분기 예측(branch prediction)** 실패나 조건부 점프에 의한 클럭 사이클 차이를 제거하기 위해, 제어 흐름(control flow)을 분기하지 않고 순수 비트
연산(bitwise operation)만으로 논리를 구현하는 것입니다.

## 주요 설계 및 보안 고려사항

### 최적화 방지

LLVM 등의 현대 컴파일러는 비트 연산으로 구현된 로직을 분석하여 더 빠른 조건부 분기문으로 역최적화(reverse-optimization)할 가능성이 있습니다. 이를 방지하기 위해 Rust 표준 라이브러리의
`core::hint::black_box`를 사용합니다.

* **목적:** 컴파일러가 입력값과 결과값을 미리 계산하거나, 로직을 분기문으로 변경하는 것을 차단합니다.
* **한계:** `black_box`는 최적화 힌트일 뿐이며, 특정 아키텍처에서는 여전히 안전하지 않은 어셈블리가 생성될 수 있으므로 최종 바이너리에 대한 검증이 권장됩니다.

### 반환값 정책

이 모듈의 비교 연산은 일반적인 `bool`(`true`/`false`)을 반환하지 않고, 비트 마스크 형태의 `Self` 타입을 반환합니다.

* **참(True):** 모든 비트가 1 (`!0`, 예: `0xFFFFFFFF` for `u32`)
* **거짓(False):** 모든 비트가 0 (`0`, 예: `0x00000000` for `u32`)
  이러한 마스크 값은 `ct_select` 함수에서 비트 연산을 통해 조건부 값을 선택하는 데 직접 사용됩니다.

## API 상세 명세

### `ConstantTimeOps` 트레이트

모든 정수형 기본 타입(`u8` ~ `u128`, `i8` ~ `i128`, `usize`/`isize`)에 대해 구현되어 있습니다.

#### `fn ct_is_zero(self) -> Self`

값이 `0`인지 판별합니다.

* **논리:** `ct_is_nonzero`의 결과를 비트 반전(NOT)하여 반환합니다.
* **반환:** 입력이 `0`이면 `!0`(All 1s), 아니면 `0`.

#### `fn ct_is_nonzero(self) -> Self`

값이 `0`이 아닌지 판별합니다.

* **알고리즘:**
  $$\text{result} = ((x \lor -x) \gg (\text{BITS} - 1)) \ \& \ 1$$
  2의 보수 표현법에서 $0$이 아닌 모든 정수 $x$에 대해, $x$ 혹은 $-x$ 중 하나는 반드시 최상위 비트(MSB)가 $1$이 된다는 성질을 이용합니다.
* **반환:** 입력이 `0`이 아니면 `!0`(All 1s), `0`이면 `0`.

#### `fn ct_is_negative(self) -> Self`

값의 최상위 비트(MSB, Sign Bit)가 설정되어 있는지 확인합니다.

* **Unsigned 타입:** MSB가 1인 큰 수인지 판별합니다.
* **Signed 타입:** 음수인지 판별합니다.
* **구현:** 산술 시프트(arithmetic shift)의 부호 확장 문제를 피하기 위해 MSB를 추출한 후 `1`과 AND 연산하여 정규화하고, 이를 `wrapping_neg()`를 통해 마스크로 확장합니다.

#### `fn ct_eq(self, other: Self) -> Self`

두 값이 비트 단위로 동일한지 비교합니다.

* **알고리즘:**
  $$\text{diff} = a \oplus b$$
  $$\text{result} = \text{NOT}(\text{is\_nonzero}(\text{diff}))$$
  XOR 연산은 두 비트가 다를 때만 `1`을 반환하므로, $a \oplus b = 0$ 이면 두 값은 같습니다.

#### `fn ct_select(self, other: Self, mask: Self) -> Self`

마스크 값에 따라 두 입력값 중 하나를 선택합니다. (Conditional Move와 유사)

* **수식:**
  $$\text{result} = b \oplus (\text{mask} \& (a \oplus b))$$
* **동작 원리:**
    * **Case 1:** $\text{mask} = 11\dots1$ (참)인 경우:
      $$b \oplus (11\dots1 \& (a \oplus b)) = b \oplus (a \oplus b) = (b \oplus b) \oplus a = 0 \oplus a = a$$
      $\rightarrow$ `self` 반환
    * **Case 2:** $\text{mask} = 00\dots0$ (거짓)인 경우:
      $$b \oplus (00\dots0 \& (a \oplus b)) = b \oplus 0 = b$$
      $\rightarrow$ `other` 반환
* **주의사항:** `mask`는 반드시 `ConstantTimeOps`의 비교 연산 결과(`0` 또는 `!0`)여야 합니다. 임의의 정수(예: `1`)를 넣을 경우 비트가 섞인 예측 불가능한 값이 반환됩니다.

## 구현 세부 사항

이 모듈은 `macro_rules!`인 `impl_ct_ops!`를 사용하여 코드 중복을 최소화하고 모든 정수 타입에 일관된 로직을 적용합니다.

* **아키텍처 독립성:** `core::mem::size_of`를 사용하여 컴파일 타임에 타입의 비트 수(`BITS`)를 계산하므로, 32비트/64비트 아키텍처에 관계없이 정확한 MSB 위치를 참조합니다.
* **Wrapping Arithmetic:** Rust의 디버그 모드에서 오버플로우 체크로 인한 패닉을 방지하기 위해, 모든 연산에 `wrapping_neg`, `wrapping_add` 등의 래핑 연산을
  명시적으로 사용합니다.