# BLAKE2b / BLAKE3 해시 함수 (entlib-native-blake)

> Q. T. Felix (수정: 26.03.23 UTC+9)
>
> [English README](README_EN.md)

`entlib-native-blake`는 RFC 7693(BLAKE2b) 및 BLAKE3 공식 명세를 준수하는 `no_std` 호환 해시 크레이트입니다. 민감 데이터는 `SecureBuffer`(mlock)에 보관하며, Drop 시 내부 상태를 `write_volatile`로 강제 소거합니다.

## 구성

| 모듈        | 알고리즘               | 표준                   |
|-----------|--------------------|----------------------|
| `blake2b` | BLAKE2b            | RFC 7693             |
| `blake3`  | BLAKE3             | BLAKE3 공식 명세         |
| `lib`     | H'(`blake2b_long`) | RFC 9106 Section 3.2 |

---

## BLAKE2b

64비트 플랫폼에 최적화된 암호 해시 함수입니다. 최대 512비트(64바이트) 다이제스트를 생성하며, 키드(keyed) MAC 모드를 지원합니다.

### 구조체

```rust
pub struct Blake2b {
    h: [u64; 8],          // 체이닝 값 (8 × 64비트)
    t: [u64; 2],          // 바이트 카운터
    buf: SecureBuffer,    // 128바이트 입력 버퍼 (mlock)
    buf_len: usize,
    hash_len: usize,      // 1..=64
}
```

### 초기화 벡터 및 파라미터 블록

IV는 SHA-512 초기 해시 값(소수의 제곱근 소수부)에서 유래합니다.

$$h_0 = \text{IV}[0] \oplus (\text{hash\_len} \mathbin{|} (\text{key\_len} \mathbin{\ll} 8) \mathbin{|} (1 \mathbin{\ll} 16) \mathbin{|} (1 \mathbin{\ll} 24))$$

키드 모드에서는 키를 128바이트 블록으로 제로 패딩한 뒤 `buf_len = 128`로 설정하여 첫 번째 블록으로 처리합니다.

### 압축 함수

12라운드 Feistel 구조를 사용하며, 각 라운드는 SIGMA 치환에 따라 정렬된 메시지 워드를 G 함수에 적용합니다.

**G 함수 (회전: 32 / 24 / 16 / 63)**

$$a \mathrel{+}= b + x, \quad d = (d \oplus a) \ggg 32$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 24$$
$$a \mathrel{+}= b + y, \quad d = (d \oplus a) \ggg 16$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 63$$

16워드 작업 벡터 $v$는 체이닝 값 $h[0..8]$, IV, 카운터 $t$, 최종화 플래그 $f$로 초기화됩니다.

$$v[12] = \text{IV}[4] \oplus t[0], \quad v[13] = \text{IV}[5] \oplus t[1]$$
$$v[14] = \text{IV}[6] \oplus f[0], \quad v[15] = \text{IV}[7] \oplus f[1]$$

12라운드 후 체이닝 값을 갱신합니다.

$$h[i] \mathrel{\oplus}= v[i] \oplus v[i+8], \quad i \in [0, 7]$$

### 최종화

마지막 블록 처리 시 $f[0] = \texttt{0xFFFF\_FFFF\_FFFF\_FFFF}$를 설정합니다. 카운터는 `buf_len`만큼 증가하며, 버퍼 나머지는 제로 패딩됩니다. 결과는 $h$에서 LE 바이트 순으로 추출합니다.

### 메모리 보안

Drop 시 `write_volatile`로 `h[0..8]`, `t[0..2]`, `buf_len`을 소거하고 `compiler_fence(SeqCst)`로 재배치를 방지합니다.

---

## blake2b_long (H')

RFC 9106 Section 3.2에서 정의된 가변 출력 해시 함수입니다. Argon2id 블록 초기화 및 최종 태그 생성에 사용됩니다.

**입력**: `LE32(T) || input`, **출력**: T바이트

$$A_1 = \text{BLAKE2b-64}(\mathtt{LE32}(T) \mathbin{\|} \text{input})$$

- $T \le 64$: 단일 `BLAKE2b-T` 호출

- $T > 64$: $r = \lceil T/32 \rceil - 2$, $\text{last\_len} = T - 32r$

$$A_i = \text{BLAKE2b-64}(A_{i-1}), \quad i = 2, \ldots, r$$
$$A_{r+1} = \text{BLAKE2b-last\_len}(A_r)$$

$$\text{output} = A_1[0..32] \mathbin{\|} A_2[0..32] \mathbin{\|} \cdots \mathbin{\|} A_r[0..32] \mathbin{\|} A_{r+1}$$

각 단계의 중간값은 `SecureBuffer`에 보관됩니다.

---

## BLAKE3

머클 트리 구조 기반의 최신 해시 함수입니다. SIMD 및 다중 스레딩을 통한 병렬 처리가 설계 목표이며, 32바이트 고정 출력 외에 임의 길이 XOF를 지원합니다.

### 구조체

```rust
pub struct Blake3 {
    chunk_state: ChunkState,      // 현재 청크 상태
    key_words: [u32; 8],          // IV 또는 키 워드
    cv_stack: [[u32; 8]; 54],     // 체이닝 값 스택 (최대 54 레벨)
    cv_stack_len: usize,
    flags: u32,
}
```

청크 크기는 1024바이트이며, CV 스택의 최대 깊이 54는 입력 크기 $2^{54}$ KiB(약 18 EiB)를 커버합니다.

### 도메인 분리 플래그

| 플래그           | 값        | 용도          |
|---------------|----------|-------------|
| `CHUNK_START` | `1 << 0` | 청크의 첫 번째 블록 |
| `CHUNK_END`   | `1 << 1` | 청크의 마지막 블록  |
| `PARENT`      | `1 << 2` | 부모 노드 압축    |
| `ROOT`        | `1 << 3` | 루트 출력 생성    |
| `KEYED_HASH`  | `1 << 4` | 키드 모드       |

### 압축 함수

32비트 워드 기반, 7라운드 압축을 수행합니다. 16워드 상태 벡터를 초기화하고 각 라운드에서 G 함수와 메시지 치환을 적용합니다.

$$\text{state} = [cv[0..8], \text{IV}[0..4], \text{ctr\_lo}, \text{ctr\_hi}, \text{block\_len}, \text{flags}]$$

**G 함수 (회전: 16 / 12 / 8 / 7)**

$$a \mathrel{+}= b + x, \quad d = (d \oplus a) \ggg 16$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 12$$
$$a \mathrel{+}= b + y, \quad d = (d \oplus a) \ggg 8$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 7$$

각 라운드 후 메시지 워드를 `MSG_PERMUTATION`에 따라 재배열합니다. 7라운드 완료 후:

$$\text{state}[i] \mathrel{\oplus}= \text{state}[i+8], \quad \text{state}[i+8] \mathrel{\oplus}= cv[i]$$

### 트리 해싱 및 CV 스택

입력을 1024바이트 청크 단위로 처리하며, 각 청크의 체이닝 값(CV)을 스택에 누적합니다. `merge_cv_stack`은 누적된 청크 수(`total_chunks`)의 포피카운트(popcount) 불변 조건을 유지하며 부모 노드를 생성합니다.

```
total_chunks = 4 (이진: 100)이 될 때:
  스택: [CV_0, CV_1, CV_2, CV_3]
  → merge: parent(CV_2, CV_3) → P_23
  → merge: parent(CV_0, CV_1) → P_01
  → merge: parent(P_01, P_23) → root
```

이 설계는 메시지 길이를 사전에 알지 못해도 단일 패스로 머클 트리를 구성할 수 있게 합니다.

### XOF (확장 가능 출력)

루트 노드에 `ROOT` 플래그를 설정하고 카운터를 증가시켜 임의 길이 출력을 생성합니다.

$$\text{output}[64k .. 64k+64] = \text{compress}(cv_\text{root}, bw, k, bl, \text{flags} \mathbin{|} \text{ROOT}), \quad k = 0, 1, 2, \ldots$$

### 메모리 보안

Drop 시 `write_volatile`로 `key_words`, `cv_stack` 전체를 소거합니다. `ChunkState` Drop 시에도 `buf`와 `chaining_value`를 소거합니다.

---

## 사용 예시

```rust
use entlib_native_blake::{Blake2b, Blake3, blake2b_long};

// BLAKE2b-32
let mut h = Blake2b::new(32);
h.update(b"hello world");
let digest = h.finalize().unwrap();
assert_eq!(digest.as_slice().len(), 32);

// BLAKE3 (32바이트)
let mut h = Blake3::new();
h.update(b"hello world");
let digest = h.finalize().unwrap();
assert_eq!(digest.as_slice().len(), 32);

// H' — Argon2id 블록 초기화용 (1024바이트)
let out = blake2b_long(b"input", 1024).unwrap();
assert_eq!(out.as_slice().len(), 1024);
```

## 의존성

| 크레이트                          | 용도              |
|-------------------------------|-----------------|
| `entlib-native-secure-buffer` | 민감 데이터 mlock 보관 |
| `entlib-native-constant-time` | 상수-시간 연산        |
