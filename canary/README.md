# SecureBuffer Zeroization Verification

FIPS 140-3 IG 3.1 및 CC FCS_CKM.4에서 요구하는 민감 데이터 소거(Zeroization)를 수학적으로 정형화하고, 해당 속성이 테스트 스위트에 의해 검증됨을 증명함.

---

## 1. 정형 모델

### 1.1 메모리 모델

메모리 영역 $`M`$을 비트의 유한 시퀀스로 정의함.

```math
M = (b_0, b_1, \ldots, b_{n-1}), \quad b_i \in \{0, 1\}, \quad n = \texttt{capacity} \times 8
```

$`\texttt{capacity}`$는 `SecureBuffer`가 관리하는 전체 할당 크기(페이지 정렬됨)이며, 사용자 데이터 영역($`\texttt{len}`$)뿐 아니라 패딩 갭($`\texttt{len}..\texttt{capacity}`$)을 포함함.

### 1.2 소거 속성 (Zeroization Property)

**정의 (ZP)**. 소거 함수 $`Z: \{0,1\}^n \to \{0,1\}^n`$은 다음을 만족할 때 **완전**하다고 함:

```math
\forall\, M \in \{0,1\}^n : Z(M) = 0^n
```

즉, 임의의 초기 메모리 상태에 대해 소거 후 모든 비트가 0이어야 함.

### 1.3 비트 독립성 (Bit Independence)

소거가 완전함을 증명하려면, 각 비트 위치 $`i`$에 대해 $`1 \to 0`$ 전환이 독립적으로 발생함을 보여야 함.

**보조정리 1 (비트별 소거)**. 비트 위치 $`i`$ ($`0 \le i < n`$)에 대해:

```math
\forall\, i : \exists\, M \text{ s.t. } M[i] = 1 \;\land\; Z(M)[i] = 0
```

이는 "모든 비트 위치에서 1이 0으로 전환될 수 있다"는 것을 의미함.

**보조정리 2 (보수 완전성)**. 두 메모리 상태 $`M_a`$, $`M_b`$가 비트 보수(bitwise complement)이면:

```math
M_a \oplus M_b = 1^n
```

$`M_a`$와 $`M_b`$ 모두에 대해 $`Z(M_a) = Z(M_b) = 0^n`$이 성립하면, 모든 비트 위치에서 $`1 \to 0`$ 전환이 독립적으로 검증됨. $`M_a[i] = 1`$인 위치와 $`M_b[i] = 1`$인 위치의 합집합이 전체 비트 집합이기 때문임.

```math
\{i \mid M_a[i] = 1\} \cup \{i \mid M_b[i] = 1\} = \{0, 1, \ldots, n-1\}
```

---

## 2. 테스트에 의한 증명

### 2.1 JO(Java-Owned) 패턴 검증 (`zeroize_jo.rs`)

| 테스트 | 포이즌 | 비트 패턴 | 검증 대상 |
|---|---|---|---|
| `jo_zeroize_0xff_all_bits_set` | $`\texttt{0xFF}`$ | $`11111111_2`$ | 보조정리 1의 충분조건 |
| `jo_zeroize_0xaa_even_bits` | $`\texttt{0xAA}`$ | $`10101010_2`$ | 짝수 비트 위치 소거 |
| `jo_zeroize_0x55_odd_bits` | $`\texttt{0x55}`$ | $`01010101_2`$ | 홀수 비트 위치 소거 |
| `jo_zeroize_complement_pair` | $`\texttt{0xAA} + \texttt{0x55}`$ | 보수 쌍 | 보조정리 2 적용 |
| `jo_zeroize_sequential_all_byte_values` | $`\texttt{0x00}..\texttt{0xFF}`$ | 전체 바이트 공간 | $`2^8`$가지 바이트 값의 소거 가능성 |

**증명 (비트 독립성)**.

$`\texttt{0xAA} = 10101010_2`$에 대해 $`Z`$ 적용 후 0이면, 비트 위치 $`\{1, 3, 5, 7\}`$ (LSB 기준)에서 $`1 \to 0`$ 전환이 확인됨.

$`\texttt{0x55} = 01010101_2`$에 대해 $`Z`$ 적용 후 0이면, 비트 위치 $`\{0, 2, 4, 6\}`$에서 $`1 \to 0`$ 전환이 확인됨.

```math
\{1,3,5,7\} \cup \{0,2,4,6\} = \{0,1,2,3,4,5,6,7\}
```

이므로 바이트 내 모든 비트 위치에서 독립 소거가 검증됨. 이를 $`\texttt{capacity}`$ 전체(4096바이트 = 32768비트)에 대해 반복하므로, 전체 메모리 영역의 비트 독립성이 증명됨.

### 2.2 RO(Rust-Owned) 패턴 검증 (`zeroize_ro.rs`)

RO 패턴에서는 $`\texttt{len} < \texttt{capacity}`$인 패딩 갭이 존재함.

![secure-buffer-std.png](../public/assets/secure-buffer-std.png)

| 테스트                                              | 검증 대상                                                                   |
|--------------------------------------------------|-------------------------------------------------------------------------|
| `ro_full_capacity_zeroed_including_padding_gap`  | 전체 $`\texttt{capacity}`$($`\texttt{len}`$ + padding) 소거                 |
| `ro_padding_gap_explicitly_poisoned_then_zeroed` | 패딩 갭에 명시적 포이즌 주입 후 소거 확인                                                |
| `ro_complement_patterns`                         | RO 패턴에서 비트 독립성($`\texttt{0xAA}`$, $`\texttt{0x55}`$, $`\texttt{0xFF}`$) |

**증명 (패딩 갭 소거)**. `SecureBuffer::drop()`은 `Zeroizer::zeroize_raw(ptr, capacity)`를 호출하며, $`\texttt{capacity} \ge \texttt{len}`$이 항상 성립함. 테스트에서 $`\texttt{len}=100`$, $`\texttt{capacity}=4096`$으로 설정하고 전체 4096바이트를 포이즌한 뒤 `Drop` 후 전수 스캔함. 바이트 $`[100, 4095]`$(패딩 갭)이 0임이 확인되면, 패딩 영역의 소거가 보장됨.

### 2.3 다중 페이지 검증 (`zeroize_multi_page.rs`)

| 테스트                                       | 페이지 수       | 검증 대상        |
|-------------------------------------------|-------------|--------------|
| `multi_page_3_pages`                      | 3 (12288B)  | 다중 페이지 소거    |
| `multi_page_10_pages`                     | 10 (40960B) | 대용량 소거       |
| `page_boundary_bytes_explicitly_verified` | 3           | 경계 오프바이원     |
| `ro_multi_page_padding_gap`               | $`\ge 2`$   | RO 다중 페이지 패딩 |

**증명 (페이지 경계 안전성)**. 캐시 라인 플러시 루프가 페이지 경계에서 오프바이원 결함을 가질 수 있음:

```asm
.loop:
    clflush [flush_ptr]
    add     flush_ptr, cache_line_size
    cmp     flush_ptr, end_ptr
    jb      .loop
```

`page_boundary_bytes_explicitly_verified`는 오프셋 $`\{0,\; 4095,\; 4096,\; 4097,\; 8191,\; 8192,\; 8193,\; 12287\}`$을 명시적으로 검사하여, 페이지 경계 전후의 바이트가 누락 없이 소거됨을 확인함.

### 2.4 패닉 경로 검증 (`absolute.rs`)

Rust의 스택 해제(stack unwinding)에서 `Drop` 트레이트가 올바르게 호출되는지 검증함.

| 테스트                              | 검증 대상                   |
|----------------------------------|-------------------------|
| `panic_survival_0xff`            | 패닉 후 RAII `Drop`에 의한 소거 |
| `panic_survival_0xaa`            | 패닉 + 짝수 비트              |
| `panic_survival_0x55`            | 패닉 + 홀수 비트              |
| `panic_survival_complement_pair` | 패닉 경로 비트 독립성            |

**증명 (패닉 안전성)**. `catch_unwind` 내에서 `SecureBuffer` 생성 후 `panic!()` 발생 시, Rust의 unwind 메커니즘이 스택 프레임을 역순으로 정리하며 `SecureBuffer::drop()`을 호출함. 테스트 프로필은 $`\texttt{panic} = \texttt{"unwind"}`$(Cargo 기본값)를 사용하므로 `catch_unwind`가 정상 동작함.

---

## 3. 하드웨어 수준 보장

소프트웨어 테스트로 검증할 수 없는 하드웨어 수준의 보장은 구현 코드의 정적 분석으로 확인함.

### 3.1 컴파일러 DSE(Dead Store Elimination) 방지

| 아키텍처        | 메커니즘                                     | 근거                        |
|-------------|------------------------------------------|---------------------------|
| x86_64      | `rep stosb` (인라인 어셈블리)                   | 컴파일러가 `asm!` 블록을 제거할 수 없음 |
| AArch64     | `write_volatile` 루프                      | volatile 시맨틱이 DSE를 원천 차단함 |
| 기타 (std)    | `explicit_bzero` / `RtlSecureZeroMemory` | OS 커널이 보장하는 소거 API        |
| 기타 (no_std) | `write_volatile` 루프                      | volatile 시맨틱              |

모든 경로에서 `compiler_fence(SeqCst)` + `fence(SeqCst)`가 후속하여 컴파일러 및 하드웨어 파이프라인 재배치를 방지함.

### 3.2 캐시 라인 플러시

| 아키텍처    | 명령어                   | 보장                          |
|---------|-----------------------|-----------------------------|
| x86_64  | `clflush` + `mfence`  | 캐시에서 메인 메모리로 즉시 기록 후 무효화함   |
| AArch64 | `dc civac` + `dsb sy` | 데이터 캐시 클린 + 무효화, 전체 시스템 배리어 |

이는 소거된 0이 CPU 캐시에만 머물지 않고 물리 메모리(DRAM)에 반영됨을 보장함.

---

## 4. 커버리지 매트릭스

| 구분               | JO  | RO | Panic | Multi-Page |
|:-----------------|:---:|:--:|:-----:|:----------:|
| `0xFF` 전체 비트     |  O  | O  |   O   |     O      |
| `0xAA` 짝수 비트     |  O  | O  |   O   |     -      |
| `0x55` 홀수 비트     |  O  | O  |   O   |     -      |
| 보수 쌍 독립성         |  O  | O  |   O   |     -      |
| 숫자 카운터           |  O  | -  |   -   |     -      |
| 패딩 갭             | N/A | O  |  N/A  |     O      |
| 전체 `capacity` 스캔 |  O  | O  |   O   |     O      |

---

## 5. 실행

```bash
cargo test -p canary
```

16개 테스트가 모두 통과하면, 위 정형 모델에서 정의한 소거 속성(ZP)이 소프트웨어 수준에서 검증된 것으로 판단함.
