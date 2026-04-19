# 상수-시간 연산 표준 명세

> **크레이트**: `entlib-native-constant-time`
> **대상 플랫폼**: `x86_64`, `aarch64` (no_std)

---

## 1. 설계 목표 및 위협 모델

### 위협 모델

이 크레이트가 방어하는 공격 유형은 다음과 같다.

| 공격 유형                                    | 설명                                 | 방어 수단                             |
|------------------------------------------|------------------------------------|-----------------------------------|
| **타이밍 공격 (Timing Attack)**               | CPU 실행 시간 측정을 통한 비밀 데이터 추론         | 조건 분기 제거, 비트 마스크 연산               |
| **분기 예측 공격 (Branch Prediction Attack)**  | CPU 파이프라인 미스 예측 패턴으로 비밀 데이터 추론     | `black_box`로 LLVM SELECT 노드 생성 차단 |
| **컴파일러 역최적화 (Compiler De-optimization)** | LLVM InstCombine이 비트 연산을 조건 분기로 치환 | 중간 산출물 `black_box` 적용 위치 엄격 관리    |
| **캐시 타이밍 공격 (Cache Timing Attack)**      | 메모리 접근 패턴 측정을 통한 비밀 데이터 추론         | 데이터 독립적 메모리 접근 패턴 보장              |

### 상수-시간(Constant-Time)의 수학적 정의

두 개의 비밀 입력 $s_1$, $s_2$에 대해 프로그램의 관측 가능한 실행 궤적(Execution Trace)을 $\tau(s_1)$, $\tau(s_2)$라 하면, 상수-시간 조건은 다음과 같다.

$$\forall s_1, s_2 \in \mathcal{S} : \tau(s_1) = \tau(s_2)$$

여기서 관측 가능한 실행 궤적 $\tau$는 다음 요소를 포함한다.

- 실행된 명령어 시퀀스 (제어 흐름)
- 메모리 읽기/쓰기 주소 시퀀스
- 총 실행 사이클 수

---

## 2. `Choice` 타입 — 상수-시간 불리언

### 불변 조건 (Invariant)

```
Choice ∈ {0x00, 0xFF}
```

`Choice(u8)` 내부 필드는 반드시 두 값 중 하나만 허용된다. 이 불변 조건이 유지될 때, 비트 연산은 논리 연산과 수학적으로 동치이다.

| 값      | 의미    | 논리 연산 동치                                  |
|--------|-------|-------------------------------------------|
| `0x00` | False | `0 & x = 0`, `0 \| x = x`, `!0x00 = 0xFF` |
| `0xFF` | True  | `F & x = x`, `F \| x = F`, `!0xFF = 0x00` |

### 구조

```rust
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Choice(u8);
```

`#[repr(transparent)]`는 `u8`과 동일한 메모리 레이아웃을 보장하며, FFI 경계에서 단일 바이트로 취급된다.

### 생성자

| 생성자                              | 조건                    | 설명                                              |
|----------------------------------|-----------------------|-------------------------------------------------|
| `from_mask(mask: u8)`            | `mask ∈ {0x00, 0xFF}` | 정규화된 마스크 직접 구성. 호출자가 불변 조건을 보장해야 한다.            |
| `from_mask_normalized(mask: u8)` | 임의 `u8`               | 임의 바이트를 `0x00`/`0xFF`로 정규화. `audit_mode` 피처 한정. |

#### `from_mask_normalized` 정규화 수식

임의 바이트 $m$에 대해:

$$\text{msb\_set} = m \mid (-m)$$
$$\text{is\_nonzero} = \text{msb\_set} \gg 7$$
$$\text{result} = -\text{is\_nonzero}$$

$m = 0$이면 $\text{result} = 0\text{x00}$, $m \neq 0$이면 $\text{result} = 0\text{xFF}$.

### 비트 연산 진리표

`Choice`에 대한 비트 연산은 논리 연산과 동치이며, 모두 단일 CPU 명령어(AND, OR, XOR, NOT)로 컴파일된다.

| 연산        | A      | B      | 결과     |
|-----------|--------|--------|--------|
| AND (`&`) | `0xFF` | `0xFF` | `0xFF` |
| AND (`&`) | `0xFF` | `0x00` | `0x00` |
| AND (`&`) | `0x00` | `0x00` | `0x00` |
| OR (`\|`) | `0xFF` | `0x00` | `0xFF` |
| OR (`\|`) | `0x00` | `0x00` | `0x00` |
| XOR (`^`) | `0xFF` | `0xFF` | `0x00` |
| XOR (`^`) | `0xFF` | `0x00` | `0xFF` |
| NOT (`!`) | `0xFF` | —      | `0x00` |
| NOT (`!`) | `0x00` | —      | `0xFF` |

---

## 3. 트레이트 명세

### `ConstantTimeEq`

```rust
fn ct_eq(&self, other: &Self) -> Choice;
fn ct_ne(&self, other: &Self) -> Choice;  // 기본 구현: !ct_eq
fn ct_is_ge(&self, other: &Self) -> Choice;
```

#### `ct_eq` — 동일성 비교

**사전 조건**: 없음
**사후 조건**: `self == other` iff 반환값 `== 0xFF`

**부호 없는 정수 구현 (u8, u16, u32, u64, u128, usize)**:

$$v = A \oplus B$$
$$\text{msb} = (v \mid -v) \gg (\text{BITS} - 1)$$
$$\text{mask} = -(\text{msb as u8} \oplus 1)$$

$v = 0$ (동일) 이면 $\text{msb} = 0$, $\text{mask} = 0\text{xFF}$.
$v \neq 0$ (상이) 이면 $\text{msb} = 1$, $\text{mask} = 0\text{x00}$.

**`black_box` 적용 위치**:

```rust
let v = core::hint::black_box(*self ^ *other);
let msb = (v | v.wrapping_neg()) >> (<$t>::BITS - 1);
```

`v`에 `black_box`를 적용하는 것이 핵심이다. LLVM InstCombine은 `(v | -v) >> (BITS-1)` 패턴을 `ICMP NE(v, 0)`으로 인식하여 `JNE`/`JE` 조건 분기로 치환한다. `v`를 opaque하게 만들면 컴파일러가 `v`의 기원을 추적할 수 없으므로 패턴 매칭이 불가능해진다.

**`black_box`를 최종 mask에 적용하면 안 되는 이유**: LLVM은 실행 순서가 아닌 논리적 AST 구조를 먼저 분석한다. `black_box(mask)`는 LLVM이 이미 ICMP 노드를 생성한 이후에 개입하므로 효과가 없다.

**부호 있는 정수 구현 (i8, i16, i32, i64, i128, isize)**:

비트 패턴 비교로 위임한다. 부호 없는 정수로 캐스팅하여 산술 시프트(SAR) 취약점을 회피한다.

```rust
let a = *self as $u_type;
let b = *other as $u_type;
a.ct_eq(&b)
```

#### `ct_is_ge` — 대소 비교 (≥)

**사전 조건**: 없음
**사후 조건**: `self >= other` iff 반환값 `== 0xFF`

**부호 없는 정수 구현**: 빌림(Borrow) 방정식을 사용한다.

$$\text{sub} = A - B \pmod{2^n}$$
$$\text{borrow} = (\lnot A \land B) \mid (\lnot(A \oplus B) \land \text{sub})$$
$$\text{borrow\_msb} = \text{borrow} \gg (\text{BITS} - 1)$$
$$\text{mask} = -(\text{borrow\_msb} \oplus 1)$$

$A \geq B$이면 빌림이 없으므로 $\text{borrow\_msb} = 0$, $\text{mask} = 0\text{xFF}$.
$A < B$이면 빌림이 발생하므로 $\text{borrow\_msb} = 1$, $\text{mask} = 0\text{x00}$.

**`black_box` 적용 위치**:

```rust
let borrow = core::hint::black_box((!*self & *other) | (!(*self ^ *other) & sub));
let borrow_msb = (borrow >> (<$t>::BITS - 1)) as u8;
```

LLVM은 위 빌림 공식 전체를 `ICMP ULT(A, B)` (Unsigned Less Than)로 인식한다. `borrow` 전체를 opaque하게 만들면 이후 `(opaque >> BITS-1)`은 패턴 매칭 불가 상태가 된다.

**부호 있는 정수 구현**: 2의 보수 부호 비트 반전 기법을 사용한다.

$$\text{sign\_mask} = 1 \ll (\text{BITS} - 1)$$
$$A' = (A \text{ as unsigned}) \oplus \text{sign\_mask}$$
$$B' = (B \text{ as unsigned}) \oplus \text{sign\_mask}$$
$$\text{result} = A'\text{.ct\_is\_ge}(B')$$

MSB를 반전하면 값의 수학적 대소 순서를 보존하면서 부호 없는 도메인으로 안전하게 매핑된다.

### `ConstantTimeSelect`

```rust
fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self;
```

**사전 조건**: `choice ∈ {0x00, 0xFF}`
**사후 조건**: `choice == 0xFF` → `a` 반환, `choice == 0x00` → `b` 반환

**구현**: 부호 확장(Sign-Extension) 트릭

$$\text{mask} = (\text{choice as i8}) \text{ as } T$$
$$\text{result} = (a \land \text{mask}) \mid (b \land \lnot\text{mask})$$

`0xFF as i8 = -1`이므로, `T`로 부호 확장하면 모든 비트가 1인 `0xFFFF...`가 된다.
`0x00 as i8 = 0`이므로, `T`로 확장하면 모든 비트가 0인 `0x0000...`가 된다.

### `ConstantTimeSwap`

```rust
fn ct_swap(a: &mut Self, b: &mut Self, choice: Choice);
```

**사전 조건**: `choice ∈ {0x00, 0xFF}`
**사후 조건**: `choice == 0xFF` → `a`와 `b` 교환, `choice == 0x00` → 원래 값 유지

**구현**: 마스크된 XOR 스왑

$$\text{mask} = (\text{choice as i8}) \text{ as } T$$
$$t = (a \oplus b) \land \text{mask}$$
$$a' = a \oplus t, \quad b' = b \oplus t$$

`mask = 0xFFFF...`이면 $t = a \oplus b$로 표준 XOR 스왑이 수행된다.
`mask = 0x0000...`이면 $t = 0$으로 값이 변경되지 않는다.

Montgomery Ladder와 같은 암호학적 알고리즘의 조건부 스왑에 사용된다.

### `ConstantTimeIsZero`

```rust
fn ct_is_zero(&self) -> Choice;
```

**구현**: `self.ct_eq(&0)`으로 위임.

### `ConstantTimeIsNegative`

```rust
fn ct_is_negative(&self) -> Choice;
```

**사전 조건**: 없음
**사후 조건**: MSB = 1 iff 반환값 `== 0xFF`

**구현**:

$$\text{msb} = (A \gg (\text{BITS} - 1)) \text{ as u8} \land 1$$
$$\text{mask} = -\text{msb}$$

`msb = 1`이면 $\text{mask} = 0\text{xFF}$, `msb = 0`이면 $\text{mask} = 0\text{x00}$.

단일 우측 시프트(SHR) 명령어만 사용하므로 LLVM이 패턴 매칭할 대상이 없다. `black_box`는 MSB 추출 직후에 적용된다.

**부호 있는 정수**: 산술 시프트(SAR)의 구현 정의 동작(Implementation-Defined Behavior)을 회피하기 위해 부호 없는 정수로 캐스팅 후 논리 시프트를 수행한다.

```rust
let u_val = *self as $u_type;
let msb = core::hint::black_box((u_val >> (<$s_type>::BITS - 1)) as u8 & 1u8);
```

---

## 4. LLVM InstCombine 방어 전략

### 문제: LLVM의 패턴 인식과 역최적화

LLVM InstCombine 패스는 실행 순서가 아니라 **논리적 AST 구조**를 분석한다. 다음 패턴들이 자동으로 조건 분기로 치환된다.

| 비트 연산 패턴                              | LLVM 인식 결과       | 생성 명령어       |
|---------------------------------------|------------------|--------------|
| `(v \| v.wrapping_neg()) >> (BITS-1)` | `ICMP NE(v, 0)`  | `JNE` / `JE` |
| `(!A & B) \| (!(A^B) & (A-B))`        | `ICMP ULT(A, B)` | `JB` / `JAE` |

조건 분기가 비밀 데이터에 의존하면, 두 입력 클래스(동일/상이)가 CPU 파이프라인에서 서로 다른 실행 경로를 밟게 된다. 50% 미스 예측률에서 파이프라인 플러시로 인해 수십 사이클의 타이밍 차이가 발생한다.

### 해결: 패턴 입력에 `black_box` 적용

`core::hint::black_box`는 컴파일러에 대한 불투명 경계(Opaque Barrier)로, `black_box(x)`의 반환값이 `x`와 동일하지만 컴파일러가 `x`의 기원을 추적하지 못하게 한다.

**핵심 원칙**: `black_box`는 LLVM이 인식할 패턴의 **입력값**에 적용해야 한다. 패턴의 **출력(mask)** 에 적용하면 LLVM이 이미 ICMP 노드를 생성한 이후이므로 효과가 없다.

| 연산               | `black_box` 적용 대상                     | 차단 효과                                 |
|------------------|---------------------------------------|---------------------------------------|
| `ct_eq`          | `v = *self ^ *other`                  | `(v \| -v) >> BITS-1` → ICMP NE 인식 불가 |
| `ct_is_ge`       | `borrow = (!A & B) \| (!(A^B) & sub)` | `borrow >> BITS-1` → ICMP ULT 인식 불가   |
| `ct_is_negative` | `msb = (val >> BITS-1) as u8 & 1u8`   | 단일 SHR — 패턴 없음, 예방적 적용                |

---

## 5. 지원 타입

| 부호 없는 정수                                   | 부호 있는 정수                                   |
|--------------------------------------------|--------------------------------------------|
| `u8`, `u16`, `u32`, `u64`, `u128`, `usize` | `i8`, `i16`, `i32`, `i64`, `i128`, `isize` |

부호 있는 정수의 `ct_eq`/`ct_is_zero`/`ct_is_negative`/`ct_select`/`ct_swap`은 부호 없는 정수 구현으로 위임한다.
`ct_is_ge`는 MSB 반전을 통한 도메인 변환 후 위임한다.

---

## 6. 피처 플래그

| 피처                     | 설명                                                                                |
|------------------------|-----------------------------------------------------------------------------------|
| `default`              | 프로덕션 모드. `black_box` 최적화 방어 활성화.                                                  |
| `audit_mode`           | `from_mask_normalized` 공개. `wrapper.rs`의 `#[no_mangle]` 감사 심볼 노출.                 |
| `saw_verify`           | `audit_mode` 포함. `unwrap_u8`에서 `black_box`를 우회하여 SAW 기호 실행이 값을 추적할 수 있도록 한다.      |
| `valgrind_taint_audit` | Valgrind Memcheck의 오염 추적(Taint Tracking)으로 비밀 데이터가 조건 분기에 영향을 주는지 검증한다. Linux 한정. |

---

## 7. 검증 체계

상수-시간 보장은 세 가지 독립적인 방법으로 검증된다.

### 7.1 정형 검증 — SAW + Cryptol + Z3

Galois Software Analysis Workbench(SAW)를 사용하여 Rust LLVM 비트코드와 Cryptol 참조 명세 간의 기능적 동치성을 SMT 솔버(Z3)로 수학적으로 증명한다.

**검증 범위** (`saw/verify.saw`):

| 페이즈     | 대상                        | 수   |
|---------|---------------------------|-----|
| Phase 1 | Cryptol 명세 속성 증명          | 14개 |
| Phase 2 | LLVM 비트코드 ↔ Cryptol 동치 증명 | 10개 |

**Cryptol 속성 목록**:

```
from_mask_is_boolean     : ∀m. from_mask(m) ∈ {0x00, 0xFF}
ct_eq_correct            : (A = B) ↔ (ct_eq(A, B) = 0xFF)
ct_eq_reflexive          : ct_eq(A, A) = 0xFF
ct_eq_symmetric          : ct_eq(A, B) = ct_eq(B, A)
ct_ne_correct            : (A ≠ B) ↔ (ct_ne(A, B) = 0xFF)
ct_is_ge_correct         : (A ≥ B) ↔ (ct_is_ge(A, B) = 0xFF)
ct_is_ge_reflexive       : ct_is_ge(A, A) = 0xFF
ct_is_ge_antisymmetric   : ct_is_ge(A,B) ∧ ct_is_ge(B,A) → A = B
ct_is_ge_total           : ct_is_ge(A,B) ∨ ct_is_ge(B,A)
ct_is_zero_correct       : (A = 0) ↔ (ct_is_zero(A) = 0xFF)
ct_is_negative_correct   : (A >> 63 = 1) ↔ (ct_is_negative(A) = 0xFF)
ct_select_true           : ct_select(A, B, 0xFF) = A
ct_select_false          : ct_select(A, B, 0x00) = B
ct_swap_true             : ct_swap(A, B, 0xFF) = (B, A)
ct_swap_false            : ct_swap(A, B, 0x00) = (A, B)
choice_not_involution    : !!c = c
```

**실행**:

```bash
cd core/constant-time/saw
./docker_verify.sh
```

### 7.2 정적 분석 — 어셈블리 검사

`cc-constant-time-audit` CI 워크플로를 통해 릴리즈 빌드의 어셈블리를 분석하여 비밀 데이터 의존적 분기 명령어(`JE`, `JNE`, `JB`, `JAE`, `CMOV` 등)가 존재하는지 검사한다.

### 7.3 동적 타이밍 검증 — DudeCT

통계적 타이밍 분석으로 실제 하드웨어에서의 타이밍 누출을 검증한다.

**알고리즘**: Reparaz et al., "dudect: assessing the Constant-Time Property of Code in Practice", CHES 2017
**방법**: Welch's t-검정 (Welford 온라인 알고리즘, 수치 안정)
**환경**: Ubuntu 24.04 x86_64 베어메탈 (OS 노이즈 최소화)

| 판정 기준 | $\lvert t \rvert$ 범위              | 의미          |
|-------|-----------------------------------|-------------|
| PASS  | $< 4.5$                           | 타이밍 누출 없음   |
| WARN  | $4.5 \leq \lvert t \rvert < 10.0$ | 주의 — 재검토 필요 |
| FAIL  | $\geq 10.0$                       | 타이밍 의존성 검출  |

**측정 파라미터**: $N = 1{,}000{,}000$ 샘플, 상위 5% 이상값 제거, 기본 웜업 10,000회

```bash
cargo run --bin dudect-eval --release -- --warmup 50000
```

**측정 정밀도**: `RDTSC + LFENCE` 직렬화로 명령어 재정렬 방지

```rust
core::arch::x86_64::_mm_lfence();
core::arch::x86_64::_rdtsc()
```

**PRNG 대칭성 요구사항**: 두 클래스(동일/상이)에서 PRNG 호출 횟수가 동일해야 한다. 비대칭 호출은 CPU 마이크로-아키텍처 상태 편차를 유발하여 위음성 FAIL의 원인이 된다.

---

## 8. 보안 제약 사항

1. `Choice` 내부 필드(`u8`)는 절대로 `pub`으로 공개해선 안 된다.
2. `from_mask`의 호출자는 `mask ∈ {0x00, 0xFF}` 불변 조건을 반드시 보장해야 한다.
3. `saw_verify` 피처는 프로덕션 빌드에서 절대 활성화해선 안 된다. `black_box` 우회로 인해 타이밍 공격에 취약해진다.
4. `#[inline(always)]`를 모든 연산에 적용한다. 함수 호출 오버헤드 자체가 타이밍 차이를 유발할 수 있다.
5. 이 크레이트의 연산을 `unsafe` 블록 내에서 호출할 경우, Rust 메모리 안전 보장이 적용되지 않는 경계에서 비밀 데이터 누출 경로를 별도로 검토해야 한다.
