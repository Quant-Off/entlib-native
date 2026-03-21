# Hash_DRBG 크레이트 (entlib-native-rng)

> Q. T. Felix (수정: 26.03.21 UTC+9)
> 
> [English README](README_EN.md)

`entlib-native-rng`은 NIST SP 800-90A Rev. 1 표준의 Section 10.1.1에 명시된 Hash_DRBG(Hash-based Deterministic Random Bit Generator)를 구현하는 `no_std` 호환 크레이트입니다. 본 크레이트는 FIPS 140-3 승인 알고리즘 요건을 기준으로 설계되었으며, 내부 상태를 `SecureBuffer`로 관리하여 메모리 덤프·콜드 부트 공격에 대한 방어를 내장합니다.

## 보안 위협 모델

DRBG의 보안은 세 가지 핵심 속성에 의존합니다.

**예측 불가능성(Unpredictability)**: 공격자가 이전 출력을 전부 관찰하더라도 다음 출력을 예측할 수 없어야 합니다. Hash_DRBG는 내부 상태 $V$와 $C$를 출력에 직접 노출하지 않고, 단방향 해시 함수를 통해서만 출력을 유도함으로써 이를 보장합니다.

**상태 복원 공격 저항(State Recovery Resistance)**: 내부 상태 $V$와 $C$가 노출되더라도 이전 출력을 역산할 수 없어야 합니다. 두 값은 `SecureBuffer`에 격리되어 OS 레벨 메모리 잠금(`mlock`)과 Drop 시점의 강제 소거가 적용됩니다.

**재시드 강제(Mandatory Reseed)**: reseed 카운터가 $2^{48}$을 초과하면 `generate`가 즉시 `ReseedRequired`를 반환합니다. 이는 동일한 상태에서 과도하게 많은 출력을 생성하는 것을 구조적으로 차단합니다.

## 아키텍처

```
entlib-native-rng
├── os_entropy   (내부 모듈)  — 플랫폼별 OS 엔트로피 추출
└── hash_drbg    (내부 모듈)  — NIST SP 800-90A Hash_DRBG 구현
    ├── HashDRBGSHA224   (security_strength = 112 bits)
    ├── HashDRBGSHA256   (security_strength = 128 bits)
    ├── HashDRBGSHA384   (security_strength = 192 bits)
    └── HashDRBGSHA512   (security_strength = 256 bits)
```

유일하게 공개되는 초기화 경로는 `new_from_os`입니다. 사용자가 엔트로피를 직접 주입하는 `instantiate`는 `pub(crate)`로 제한되어 예측 가능한 시드 주입 위험을 원천 차단합니다.

## OS 엔트로피 소스

`extract_os_entropy`는 플랫폼별 직접 syscall 또는 검증된 라이브러리 함수를 통해 원시 엔트로피를 수집합니다. `getrandom` 등 외부 크레이트에 의존하지 않습니다.

| 타겟                         | 방식                                         |
|----------------------------|--------------------------------------------|
| `linux + x86_64`           | `SYS_getrandom` (318), `syscall` 명령어 직접 호출 |
| `linux + aarch64`          | `SYS_getrandom` (278), `svc #0` 명령어 직접 호출  |
| `macos` (x86_64 / aarch64) | `getentropy(2)` — libSystem FFI            |

Linux 구현은 `EINTR` 재시도 및 부분 읽기 루프를 포함하여 항상 `size` 바이트를 완전히 채웁니다. macOS의 `getentropy`는 단일 호출로 완전 채움을 보장하며 최대 256 바이트 제한이 있으나, `new_from_os`가 요청하는 최대 크기($2 \times 32 = 64$ bytes for SHA-512)는 이를 초과하지 않습니다.

수집된 엔트로피와 nonce는 `SecureBuffer`로 반환되어 `instantiate` 완료 후 Drop 시점에 자동 소거됩니다.

## Hash_DRBG 명세

### NIST SP 800-90A Rev. 1, Table 2 파라미터

| 인스턴스             | 해시      | outlen | seedlen | security_strength | 최소 엔트로피 |
|------------------|---------|--------|---------|-------------------|---------|
| `HashDRBGSHA224` | SHA-224 | 28 B   | 55 B    | 112 bits          | 14 B    |
| `HashDRBGSHA256` | SHA-256 | 32 B   | 55 B    | 128 bits          | 16 B    |
| `HashDRBGSHA384` | SHA-384 | 48 B   | 111 B   | 192 bits          | 24 B    |
| `HashDRBGSHA512` | SHA-512 | 64 B   | 111 B   | 256 bits          | 32 B    |

### Hash_df (Section 10.3.1)

Hash 유도 함수(Hash Derivation Function)는 임의 길이의 입력 연접(concatenation)으로부터 정확히 `no_of_bytes_to_return` 바이트를 유도합니다.

```math
V = \text{Hash\_df}(\text{entropy\_input} \| \text{nonce} \| \text{personalization\_string} \text{seedlen})
```

내부적으로 $`m = \lceil \text{seedlen} / \text{outlen} \rceil`$회 반복하며, 각 반복에서 카운터 바이트와 비트 수(big-endian 4 바이트)를 prefix로 해시를 계산합니다.

```math
\text{Hash\_df}[i] = H(\text{counter}_i \| \text{no\_of\_bits\_to\_return} \| \text{input\_string})
```

### Instantiate (Section 10.1.1.2)

엔트로피 입력, nonce, personalization string으로 내부 상태 $`V`$와 $`C`$를 초기화합니다.

```math
V = \text{Hash\_df}(\text{entropy\_input} \| \text{nonce} \| \text{personalization\_string},\ \text{seedlen})
```

```math
C = \text{Hash\_df}(\texttt{0x00} \| V,\ \text{seedlen})
```

`new_from_os`는 entropy_input으로 $`2 \times \text{security\_strength}`$ 바이트, nonce로 $`\text{security\_strength}`$ 바이트를 OS에 대한 **별개의 두 호출**로 수집하여 nonce 독립성을 보장합니다.

### Reseed (Section 10.1.1.3)

새로운 엔트로피로 내부 상태를 갱신합니다.

```math
V' = \text{Hash\_df}(\texttt{0x01} \| V \| \text{entropy\_input} \| \text{additional\_input},\ \text{seedlen})
```

```math
C' = \text{Hash\_df}(\texttt{0x00} \| V',\ \text{seedlen})
```

중간 스택 버퍼(`new_v`, `new_c`)는 연산 완료 후 `write_volatile`로 강제 소거됩니다.

### Generate (Section 10.1.1.4)

요청당 최대 $2^{19}$ bits(65,536 bytes)의 의사난수를 생성합니다. `additional_input`이 주어지면 먼저 내부 상태를 갱신합니다.

**additional_input 처리**:

```math
w = H(\texttt{0x02} \| V \| \text{additional\_input})
```
```math
V \leftarrow (V + w_{\text{padded}}) \bmod 2^{\text{seedlen} \times 8}
```

**출력 생성 (Hashgen)**:

내부 카운터 $`\text{data} = V`$를 복사하여 $`\lceil \text{requested\_bytes} / \text{outlen} \rceil`$회 해시합니다.

```math
W_i = H(\text{data} + i - 1),\quad \text{data 시작값} = V
```

**상태 갱신**:

```math
H = H(\texttt{0x03} \| V)
```
```math
V \leftarrow (V + H_{\text{padded}} + C + \text{reseed\_counter}) \bmod 2^{\text{seedlen} \times 8}
```

### 모듈러 덧셈 (add_mod / add_u64_mod)

내부 상태 $`V`$는 big-endian 바이트 배열로 표현됩니다. `add_mod`는 낮은 인덱스(상위 바이트)부터 올림수(carry)를 전파하는 순수 산술 연산으로 구현되어 **비밀 데이터의 값에 의존하는 분기가 존재하지 않습니다**.

> [!NOTE]
> **상수-시간 불변식**: 반복 횟수는 항상 `seedlen`(공개 상수)에 고정됩니다.
> 
> carry는 `u16` 산술 마스킹으로만 처리되어 조건 분기를 유발하지 않습니다.

## 메모리 보안

내부 상태 $`V`$, $`C`$는 `SecureBuffer`로 할당됩니다. `SecureBuffer`는 OS `mlock`으로 해당 페이지를 스왑 불가 영역에 고정하고, Drop 시 `write_volatile` 기반 소거를 수행합니다. `reseed_counter`는 `Drop` 구현 내에서 `write_volatile`로 별도 소거됩니다.

스택에 복사된 중간값(`new_v`, `new_c`, `c_copy`, `h_padded`, `w_padded`, `data`)은 모두 연산 완료 즉시 `write_volatile` 루프로 소거되어 스택 잔존 데이터 공격을 방지합니다.

## 오류 열거형 (DrbgError)

| 변형                  | 발생 조건                                   |
|---------------------|-----------------------------------------|
| `EntropyTooShort`   | entropy_input < security_strength bytes |
| `EntropyTooLong`    | 입력 길이 > $`2^{32}`$ bytes                |
| `NonceTooShort`     | nonce < security_strength / 2 bytes     |
| `InputTooLong`      | additional_input > $`2^{32}`$ bytes     |
| `InvalidArgument`   | no_of_bits 산출 오버플로우                     |
| `ReseedRequired`    | reseed_counter > $`2^{48}`$             |
| `AllocationFailed`  | SecureBuffer 할당 또는 mlock 실패             |
| `InternalHashError` | 해시 함수 내부 오류                             |
| `RequestTooLarge`   | 요청 크기 > 65,536 bytes                    |
| `OsEntropyFailed`   | OS 엔트로피 소스 접근 실패                        |

## 사용 예시

```rust
use entlib_native_rng::{HashDRBGSHA256, DrbgError};

fn generate_key() -> Result<[u8; 32], DrbgError> {
    // OS 엔트로피로 초기화 — 유일하게 허용되는 외부 초기화 경로
    let mut drbg = HashDRBGSHA256::new_from_os(Some(b"myapp-keygen-v1"))?;

    let mut key = [0u8; 32];
    drbg.generate(&mut key, None)?;
    Ok(key)
}
```

재시드 수행 예시

```rust
use entlib_native_rng::{HashDRBGSHA512, DrbgError};

fn generate_with_reseed() -> Result<(), DrbgError> {
    let mut drbg = HashDRBGSHA512::new_from_os(None)?;
    let mut buf = [0u8; 64];

    loop {
        match drbg.generate(&mut buf, None) {
            Ok(()) => break,
            Err(DrbgError::ReseedRequired) => {
                // OS 엔트로피로 재시드 후 재시도
                let entropy = [0u8; 32]; // 실제 구현에서는 OS 엔트로피 사용
                drbg.reseed(&entropy, None)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
```

## 설계 원칙 요약

본 크레이트는 세 가지 수준의 보안 설계를 적용합니다.

1. **표준 준수**: NIST SP 800-90A Rev. 1의 Hash_DRBG 알고리즘을 명세 단계별로 정확히 구현하며, Table 2의 파라미터를 매크로 단위로 강제합니다.
2. **메모리 격리**: 비밀 내부 상태 $`V`$, $`C`$를 `SecureBuffer`에 격리하고, 스택 복사본은 `write_volatile`로 즉시 소거하여 메모리 잔존 공격 표면을 최소화합니다.
3. **엔트로피 무결성**: 유일한 초기화 경로를 `new_from_os`로 제한하고, entropy_input과 nonce를 별개 OS 호출로 수집하여 외부 공격자가 시드를 제어할 수 없도록 합니다.
