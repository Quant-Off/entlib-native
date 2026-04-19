# Argon2id 패스워드 해시 함수 (entlib-native-argon2id)

> Q. T. Felix (수정: 26.03.23 UTC+9)
> 
> [English README](README_EN.md)

`entlib-native-argon2id`는 RFC 9106 및 NIST SP 800-63B를 준수하는 `no_std` 호환 Argon2id 패스워드 해시 크레이트입니다. BLAKE2b를 내부 해시 함수로, BLAMKA 혼합 함수를 메모리 경화 연산으로 사용하며, 민감 데이터는 전적으로 `SecureBuffer`(mlock)에 보관합니다.

## 보안 위협 모델

GPU 및 ASIC 기반 대규모 병렬 공격은 메모리 대역폭이 아닌 연산 능력에 의존하는 해시 함수를 빠르게 무력화합니다. Argon2id는 다음 세 가지 공격 경로를 동시에 차단하도록 설계되었습니다.

- **연산 경화(Computation-Hardness)**: 시간 비용 파라미터 `t`가 반복 횟수를 강제하여 최소 연산량을 보장합니다.
- **메모리 경화(Memory-Hardness)**: 메모리 비용 파라미터 `m`이 KiB 단위의 작업 메모리를 강제하여 ASIC의 다이 면적 이점을 무력화합니다.
- **부채널 저항(Side-Channel Resistance)**: 패스 0의 슬라이스 0–1을 Argon2i(데이터 독립 주소 지정) 모드로 처리하여 시간 기반 부채널 공격의 입지를 제거합니다.

## 핵심 추상화: Argon2id 구조체

`Argon2id` 구조체는 RFC 9106 파라미터를 캡슐화하며, 생성 시점에 유효성 검사를 수행합니다.

```rust
pub struct Argon2id {
    time_cost:   u32,  // t ≥ 1
    memory_cost: u32,  // m ≥ 8p (KiB)
    parallelism: u32,  // p ∈ [1, 2²⁴−1]
    tag_length:  u32,  // τ ≥ 4
}
```

내부 상태는 없으며, `hash` 메서드 호출마다 독립적인 연산 흐름이 생성됩니다.

## 알고리즘 구조

### H0: 초기 해시

패스워드, 솔트, 비밀 값, 연관 데이터 및 모든 파라미터를 단일 BLAKE2b-64 호출로 압축합니다.

$$H_0 = \text{BLAKE2b-64}(p \mathbin{\|} \tau \mathbin{\|} m \mathbin{\|} t \mathbin{\|} v \mathbin{\|} y \mathbin{\|} \ell(P) \mathbin{\|} P \mathbin{\|} \ell(S) \mathbin{\|} S \mathbin{\|} \ell(K) \mathbin{\|} K \mathbin{\|} \ell(X) \mathbin{\|} X)$$

### 초기 블록

각 레인 $i$의 첫 두 블록을 H'(가변 출력 BLAKE2b, RFC 9106 Section 3.2)로 초기화합니다.

$$B[i][0] = H'(H_0 \mathbin{\|} \mathtt{LE32}(0) \mathbin{\|} \mathtt{LE32}(i))$$
$$B[i][1] = H'(H_0 \mathbin{\|} \mathtt{LE32}(1) \mathbin{\|} \mathtt{LE32}(i))$$

H'는 출력 길이 ≤ 64바이트이면 단일 BLAKE2b 호출로 처리하고, 초과 시 중간 체인($r = \lceil T/32 \rceil - 2$, 각 64바이트 해시의 앞 32바이트를 이어 붙인 뒤 최종 `last_len`바이트 해시를 덧붙임)으로 구성됩니다.

### 세그먼트 채우기 및 Argon2id 하이브리드 모드

블록 배열은 $p$개의 레인으로 나뉘며, 각 레인은 $q = m'/p$개의 블록을 포함합니다. 레인은 4개의 동기화 지점(SYNC\_POINTS)으로 분할된 세그먼트 단위로 처리됩니다.

| 패스  | 슬라이스 | 주소 지정 모드         |
|-----|------|------------------|
| 0   | 0, 1 | 데이터 독립 (Argon2i) |
| 0   | 2, 3 | 데이터 의존 (Argon2d) |
| ≥ 1 | 모두   | 데이터 의존 (Argon2d) |

**데이터 독립 모드(Argon2i)**: 의사난수를 입력 블록으로부터 직접 읽지 않고, 별도의 주소 블록(`addr_block`)에서 취득합니다. 주소 블록은 카운터 기반 입력(`addr_input`)에 `block_g`를 두 번 적용하여 생성됩니다. 이로써 참조 인덱스가 비밀 메모리 내용에 의존하지 않습니다.

**데이터 의존 모드(Argon2d)**: 이전 블록(`B[lane][prev]`)의 첫 번째 64비트 워드를 의사난수로 사용합니다.

### phi 함수: 참조 블록 선택

의사난수 $J_1$(하위 32비트), $J_2$(상위 32비트)로부터 참조 레인 $l$과 참조 열 $z$를 결정합니다.

$$x = \left\lfloor J_1^2 / 2^{32} \right\rfloor, \quad y = \left\lfloor |R| \cdot x / 2^{32} \right\rfloor$$
$$z = (\text{start} + |R| - 1 - y) \bmod q$$

여기서 $|R|$은 참조 가능 영역 크기이며, `start`는 패스·슬라이스 조합에 따라 결정됩니다. 이 공식은 균등 분포에 근사하는 이차 함수 샘플링으로, 최근 블록에 더 높은 선택 확률을 부여합니다.

### 최종화

모든 패스 완료 후 각 레인의 마지막 블록을 XOR하여 최종 블록 $C$를 구성하고, H'로 태그를 추출합니다.

$$C = \bigoplus_{i=0}^{p-1} B[i][q-1], \quad \text{tag} = H'(C, \tau)$$

## BLAMKA 혼합 함수

BLAMKA(BLAke2 Mixed cAr Key Algorithm)는 BLAKE2b의 G 함수에 64비트 곱셈 항을 추가하여 메모리 경화성을 강화한 혼합 함수입니다.

### G_B 함수

$$a \mathrel{+}= b + 2 \cdot (a_{32} \cdot b_{32}), \quad d = (d \oplus a) \ggg 32$$
$$c \mathrel{+}= d + 2 \cdot (c_{32} \cdot d_{32}), \quad b = (b \oplus c) \ggg 24$$
$$a \mathrel{+}= b + 2 \cdot (a_{32} \cdot b_{32}), \quad d = (d \oplus a) \ggg 16$$
$$c \mathrel{+}= d + 2 \cdot (c_{32} \cdot d_{32}), \quad b = (b \oplus c) \ggg 63$$

여기서 $a_{32} = a \mathbin{\&} \texttt{0xFFFF\_FFFF}$(하위 32비트)입니다. 곱셈 항 $2 \cdot a_{32} \cdot b_{32}$은 ASIC에서 병렬 처리 비용을 증가시켜 하드웨어 저항성을 제공합니다.

### block_g 함수

1024바이트(128 × u64) 블록에 대한 Argon2 혼합 함수입니다.

$$R = X \oplus Y$$
$$Z = \text{BLAMKA}(R)$$
$$\text{dst} = R \oplus Z \quad (\text{XOR 모드이면 } \text{dst} \mathrel{\oplus}= R \oplus Z)$$

BLAMKA 순열은 블록을 8행 × 8열의 행렬(각 셀 = 2 u64)로 해석하여 행 우선, 열 우선으로 `blamka_round`를 적용합니다.

- **행 처리**: 연속된 16개 워드(`row * 16 .. row * 16 + 16`)에 1회 적용, 8회 반복
- **열 처리**: 스트라이드 패턴 `z[row * 16 + col * 2 + offset]`으로 16개 워드를 추출하여 적용, 8회 반복

## 메모리 보안

| 메커니즘                     | 적용 대상                      |
|--------------------------|----------------------------|
| `SecureBuffer` (mlock)   | H0, 태그, BLAKE2b 내부 상태      |
| `write_volatile`         | 연산 완료 후 작업 메모리 전체 소거       |
| `compiler_fence(SeqCst)` | 컴파일러가 소거 연산을 재배치·제거하는 것 방지 |

작업 블록 배열(`Vec<[u64; 128]>`)은 소거 후 drop됩니다. 소거는 각 워드에 `write_volatile(ptr, 0u64)`을 직접 호출하여 컴파일러 최적화 경로를 우회합니다.

## 파라미터 유효성 검사 (RFC 9106)

| 파라미터          | 조건                  |
|---------------|---------------------|
| `time_cost`   | ≥ 1                 |
| `memory_cost` | ≥ 8 × `parallelism` |
| `parallelism` | 1 ≤ p ≤ 2²⁴ − 1     |
| `tag_length`  | ≥ 4                 |
| `salt`        | ≥ 8바이트 (호출 시 검사)    |

세그먼트 길이 `sl = q / 4`가 2 미만이면 메모리가 지나치게 작은 것으로 판단하여 오류를 반환합니다.

## 사용 예시

```rust
use entlib_native_argon2id::Argon2id;

// NIST SP 800-63B 권고: m ≥ 19456 KiB, t ≥ 2, p = 1
let params = Argon2id::new(2, 19456, 1, 32).unwrap();
let tag = params.hash(
    b"correct horse battery staple",
    b"random_salt_16b!",
    &[],
    &[],
).unwrap();
assert_eq!(tag.as_slice().len(), 32);
```

## 테스트 벡터

RFC 9106 Appendix B.4 공식 테스트 벡터를 내장합니다.

| 파라미터          | 값                                                                         |
|---------------|---------------------------------------------------------------------------|
| `time_cost`   | 3                                                                         |
| `memory_cost` | 32 KiB                                                                    |
| `parallelism` | 4                                                                         |
| `tag_length`  | 32                                                                        |
| `password`    | `0x01` × 32                                                               |
| `salt`        | `0x02` × 16                                                               |
| `secret`      | `0x03` × 8                                                                |
| `ad`          | `0x04` × 12                                                               |
| 예상 태그         | `0d640df5 8d78766c 08c037a3 4a8b53c9 d01ef045 2d75b65e b52520e9 6b01e659` |

## 의존성

| 크레이트                          | 용도                           |
|-------------------------------|------------------------------|
| `entlib-native-blake`         | BLAKE2b 및 H'(`blake2b_long`) |
| `entlib-native-secure-buffer` | 민감 데이터 mlock 보관              |
