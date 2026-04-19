# ML-KEM 크레이트 (entlib-native-mlkem)

> Q. T. Felix (수정: 26.03.26 UTC+9)
>
> [English README](README_EN.md)

`entlib-native-mlkem`은 NIST FIPS 203 명세에 따른 모듈 격자 기반 키 캡슐화 메커니즘(Module Lattice-based Key-Encapsulation Mechanism, ML-KEM)의 구현 크레이트입니다. ML-KEM은 양자 컴퓨터에 내성을 갖는 키 교환 메커니즘으로, NIST가 2024년 최종 표준화한 후양자 암호(Post-Quantum Cryptography) 알고리즘입니다. 본 크레이트는 ML-KEM-512, ML-KEM-768, ML-KEM-1024 세 파라미터 셋 모두를 지원하며, 모든 연산 경로에서 상수-시간 처리와 `SecureBuffer` 기반 메모리 보호를 강제합니다.

## 파라미터 셋

FIPS 203은 세 가지 보안 강도 수준에 대응하는 파라미터 셋을 정의합니다. 각 파라미터 셋은 모듈 차원 $k$, 오류 분포 파라미터 $\eta_1, \eta_2$, 압축 비트 수 $d_u, d_v$에 의해 특성화됩니다.

| 파라미터 셋    | NIST 카테고리      | $k$ | $\eta_1$ | $\eta_2$ | $d_u$ | $d_v$ | ek 크기  | dk 크기  | 암호문 크기 |
|---------------|:------------------:|:---:|:---------:|:---------:|:-----:|:-----:|--------:|--------:|-----------:|
| ML-KEM-512    | 1 (AES-128 동급)   |  2  |     3     |     2     |  10   |   4   |  800 B  | 1632 B  |    768 B   |
| ML-KEM-768    | 3 (AES-192 동급)   |  3  |     2     |     2     |  10   |   4   | 1184 B  | 2400 B  |   1088 B   |
| ML-KEM-1024   | 5 (AES-256 동급)   |  4  |     2     |     2     |  11   |   5   | 1568 B  | 3168 B  |   1568 B   |

## 유한체 산술: `field` 모듈

ML-KEM의 모든 다항식 연산은 소수 $q = 3329$ 위의 유한체 $\mathbb{Z}_q$에서 수행됩니다. `field` 모듈은 $\mathbb{Z}_q$ 위의 네 가지 기본 산술 연산(덧셈, 뺄셈, 곱셈, 리덕션)을 상수-시간으로 구현합니다.

`add_q`와 `sub_q`는 분기 명령어(branch instruction) 없이 산술 시프트 기반 마스크 선택으로 모듈러 환원을 수행합니다. 덧셈의 경우 합에서 $q$를 뺀 차이값의 부호 비트를 31비트 우측 시프트하여 마스크를 생성하고, 이 마스크로 원래 합과 환원된 값 사이를 선택합니다. 뺄셈도 동일한 기법으로 음수 결과에 $q$를 더할지 결정합니다.

```rust
let d = sum - Q;
let mask = d >> 31;
(d & !mask) | (sum & mask)
```

`mul_q`는 `i64` 중간값을 경유하여 오버플로 없이 곱셈 후 유클리드 나머지 연산을 수행합니다. `reduce_q`는 임의의 `i32` 값을 $[0, q-1]$ 범위로 환원합니다.

## 수론적 변환(NTT): `ntt` 모듈

ML-KEM은 다항식환 $\mathbb{Z}_q[X]/(X^{256}+1)$ 위에서 동작하며, 다항식 곱셈의 효율적 수행을 위해 수론적 변환(Number Theoretic Transform)을 사용합니다. $q = 3329$에 대해 원시 256차 단위근 $\zeta = 17$이 존재하며($17^{256} \equiv 1 \pmod{3329}$), 이를 기반으로 NTT를 정의합니다.

### 트위들 팩터 사전 계산

NTT에 사용되는 트위들 팩터(twiddle factor)는 컴파일 시점에 `const fn`으로 사전 계산됩니다. `ZETAS` 배열은 $\zeta_i = 17^{\text{brv}_7(i+1)} \bmod q$ ($i = 0, \ldots, 126$)로 정의되며, 여기서 $\text{brv}_7$은 7-bit 역전(bit-reversal) 함수입니다. `MULZETAS` 배열은 `BaseMul`(FIPS 203 Algorithm 11)에 사용되는 128개의 감마 값 $\gamma_i = 17^{2 \cdot \text{brv}_7(i) + 1} \bmod q$를 보유합니다. 두 배열 모두 런타임 연산 없이 정적으로 바이너리에 포함됩니다.

### 순방향 NTT (Algorithm 8)

`ntt` 함수는 FIPS 203 Algorithm 8(NTT)을 구현합니다. 길이 128에서 시작하여 매 단계마다 반으로 줄어드는 Cooley–Tukey 버터플라이 구조를 사용합니다. 각 버터플라이 단계에서 $t = \zeta_k \cdot f[j + \text{len}] \bmod q$를 계산한 후 $f[j + \text{len}] = f[j] - t$, $f[j] = f[j] + t$를 수행합니다. 모든 중간 산술은 `field` 모듈의 상수-시간 함수(`mul_q`, `add_q`, `sub_q`)를 사용합니다.

### 역방향 NTT (Algorithm 9)

`intt` 함수는 FIPS 203 Algorithm 9(NTT$`^{-1}`$)를 구현합니다. 길이 2에서 시작하여 매 단계마다 두 배로 증가하는 Gentleman–Sande 버터플라이 구조를 사용하며, `ZETAS` 배열을 역순으로 참조합니다. 변환 완료 후 모든 계수에 $`128^{-1} \bmod q = 3303`$을 곱하여 스케일링을 보정합니다($`3329 = 26 \times 128 + 1`$이므로 $`128^{-1} \equiv -26 \equiv 3303 \pmod{3329}`$).

### BaseMul 및 MultiplyNTTs (Algorithm 10–11)

NTT 도메인에서의 다항식 곱셈은 128개의 독립적인 `BaseMul` 연산으로 분해됩니다. 각 `BaseMul`은 $\mathbb{Z}_q[X]/(X^2 - \gamma_i)$ 위의 1차 다항식 곱셈입니다.

$$c_0 = a_0 b_0 + a_1 b_1 \gamma_i, \quad c_1 = a_0 b_1 + a_1 b_0$$

`multiply_ntts`는 이 128회 `BaseMul`을 순차 실행하여 완전한 NTT 도메인 곱셈 결과를 생성합니다.

## 다항식 구조: `poly` 모듈

`poly` 모듈은 NTT 기반 격자 연산에 필요한 대수적 구조를 세 계층으로 정의합니다.

`Poly`는 $\mathbb{Z}_q[X]/(X^{256}+1)$ 위의 단일 다항식으로, 256개의 `i32` 계수(각각 $[0, q-1]$ 범위)를 보유합니다. 덧셈(`add`), 뺄셈(`sub`), NTT/INTT 변환, NTT 도메인 곱셈(`ntt_mul`)을 지원합니다.

`PolyVec<K>`는 $K$개의 `Poly`로 구성된 벡터이며, 벡터 덧셈과 일괄 NTT/INTT 변환을 지원합니다. `PolyMatrix<K>`는 $K \times K$ NTT 도메인 다항식 행렬로, 행렬-벡터 곱(`mul_vec`: $\hat{A} \cdot \hat{s}$)과 전치 행렬-벡터 곱(`mul_vec_transposed`: $\hat{A}^T \cdot \hat{r}$)을 제공합니다. `inner_product` 함수는 두 NTT 도메인 벡터의 내적 $\sum_{i=0}^{K-1} \hat{a}_i \circ \hat{b}_i$을 계산합니다.

## 샘플링: `sample` 모듈

`sample` 모듈은 FIPS 203이 정의하는 두 가지 확률적 샘플링 알고리즘을 구현합니다.

### SampleNTT (Algorithm 6)

`sample_ntt`는 SHAKE128 기반 확장 가능 출력 함수(XOF)를 사용하여 균일 분포의 NTT 도메인 다항식을 생성합니다. 시드 $\rho \| i \| j$ (34바이트)를 SHAKE128에 입력하고, 840바이트를 추출한 뒤 3바이트 단위로 두 개의 12-bit 값을 리틀 엔디안으로 파싱합니다. 파싱된 값이 $q$ 미만인 경우에만 계수로 채택하는 거부 샘플링(rejection sampling)을 적용합니다. 840바이트의 헤드룸은 256개 계수를 채우기에 압도적으로 충분하나, 이론적 부족 시 `MLKEMError::InternalError`를 반환합니다.

```rust
let d1 = b0 | ((b1 & 0x0F) << 8);
let d2 = (b1 >> 4) | (b2 << 4);
```

### SamplePolyCBD (Algorithm 7)

`sample_poly_cbd`는 중심 이항 분포(Centered Binomial Distribution, $\text{CBD}_\eta$)에서 다항식 계수를 샘플링합니다. SHAKE256 기반 의사 난수 함수(PRF)로 $64\eta$ 바이트를 생성한 뒤, 계수당 $2\eta$ 비트를 소비하여 $x - y$를 계산합니다($x$와 $y$는 각각 $\eta$개 비트의 합). 결과 계수는 $[-\eta, \eta]$ 범위이며, `reduce_q`를 통해 $[0, q-1]$로 환원됩니다.

## 바이트 인코딩 및 압축: `encode` 모듈

`encode` 모듈은 FIPS 203 Algorithm 3–5에 정의된 압축/복원 및 바이트 인코딩/디코딩을 구현합니다.

### Compress/Decompress (Algorithm 3)

`compress`는 $\mathbb{Z}_q$ 원소를 $d$-bit 범위로 압축합니다: $\text{Compress}_d(x) = \lfloor 2^d / q \cdot x \rceil \bmod 2^d$. 반올림은 $(x \cdot 2^d + \lfloor q/2 \rfloor) / q$의 정수 나눗셈으로 수행됩니다. `decompress`는 역연산으로, $\text{Decompress}_d(x) = \lfloor q / 2^d \cdot x \rceil$을 계산합니다. 두 함수 모두 `i64` 중간값을 사용하여 32-bit 오버플로를 방지합니다.

### ByteEncode/ByteDecode (Algorithm 4–5)

`byte_encode`는 256개의 $d$-bit 계수를 $256d/8$ 바이트의 비트 스트림으로 직렬화합니다. 각 계수를 LSB부터 비트 단위로 출력 바이트 배열에 배치합니다. `byte_decode`는 역연산으로, 비트 스트림에서 $d$-bit 값을 순차 추출합니다. $d = 12$인 경우 마스크를 `0xFFF`로 고정하여 모듈러스 $q$ 이하의 전체 표현 범위를 허용합니다.

`compress_and_encode`와 `decode_and_decompress`는 압축과 인코딩, 디코딩과 복원을 각각 결합하여 K-PKE의 암호문 생성/파싱에 사용됩니다.

## K-PKE 내부 암호화 스킴: `k_pke` 모듈

`k_pke` 모듈은 FIPS 203 Algorithm 12–14에 정의된 내부 CPA-보안 공개 키 암호화 스킴(K-PKE)을 구현합니다. ML-KEM의 IND-CCA2 보안은 이 K-PKE를 Fujisaki–Okamoto(FO) 변환으로 감싸서 달성됩니다.

### K-PKE.KeyGen (Algorithm 12)

`k_pke_keygen`은 32바이트 시드 $d$로부터 키 쌍을 결정론적으로 생성합니다. $G(d \| k) = \text{SHA3-512}(d \| k)$를 통해 시드를 $(\rho, \sigma)$로 분할한 뒤, $\rho$로부터 $K \times K$ NTT 행렬 $\hat{A}$를 샘플링하고, $\sigma$로부터 비밀 벡터 $s$와 오류 벡터 $e$를 $`\text{CBD}_{\eta_1}`$ 분포에서 샘플링합니다. 공개 키 벡터 $`\hat{t} = \hat{A} \cdot \hat{s} + \hat{e}`$를 NTT 도메인에서 계산하고, 캡슐화 키 $`\text{ek} = \text{ByteEncode}_{12}(\hat{t}) \| \rho`$와 비밀 키 $`\text{dk} = \text{ByteEncode}_{12}(\hat{s})`$를 출력합니다. 비밀 키 $\text{dk}$는 `SecureBuffer`에 보관되어 OS 메모리 잠금이 적용됩니다.

### K-PKE.Encrypt (Algorithm 13)

`k_pke_encrypt`는 캡슐화 키 $\text{ek}$, 32바이트 메시지 $m$, 32바이트 난수 $r$을 입력받아 암호문을 생성합니다. $r$로부터 랜덤 벡터 $\mathbf{r}$, 오류 벡터 $e_1$, 오류 스칼라 $e_2$를 샘플링합니다. 암호문은 두 성분으로 구성됩니다:

$$\mathbf{u} = \text{NTT}^{-1}(\hat{A}^T \cdot \hat{\mathbf{r}}) + e_1, \quad v = \text{NTT}^{-1}(\hat{t}^T \cdot \hat{\mathbf{r}}) + e_2 + \lceil q/2 \rceil \cdot m$$

$\mathbf{u}$의 각 성분은 $d_u$-bit로, $v$는 $d_v$-bit로 압축 후 바이트 인코딩됩니다.

### K-PKE.Decrypt (Algorithm 14)

`k_pke_decrypt`는 비밀 키 $\text{dk}$와 암호문 $c$로부터 메시지를 복원합니다. 암호문을 디코딩/복원하여 $\mathbf{u}$와 $v$를 얻고, $w = v - \text{NTT}^{-1}(\hat{s}^T \cdot \text{NTT}(\mathbf{u}))$를 계산한 뒤, $\text{Compress}_1(w)$를 통해 각 계수를 0 또는 1로 양자화하여 원본 메시지 비트를 복원합니다.

### 해시 함수

`k_pke` 모듈은 FIPS 203이 명시하는 세 가지 해시 함수 인터페이스를 내부적으로 정의합니다:
- $G$: SHA3-512 (64바이트 출력) — 시드 분할 및 공유 비밀 유도
- $H$: SHA3-256 (32바이트 출력) — 캡슐화 키 해시
- $J$: SHAKE256 (32바이트 출력) — 암묵적 거부 키 유도

## ML-KEM 최상위 인터페이스: `lib` 모듈

`lib` 모듈은 FIPS 203 Algorithm 16–21에 대응하는 공개 API를 제공합니다.

### RNG 추상화

`MLKEMRng` 트레이트는 ML-KEM 연산에 필요한 암호학적 난수 생성기 인터페이스를 정의합니다. `HashDRBGRng`는 NIST SP 800-90A Rev.1 Hash_DRBG(SHA-512 기반, Security Strength 256-bit)의 래퍼로, OS 엔트로피 소스(`getrandom(2)` / `getentropy(2)`)로부터만 초기화됩니다. 내부 상태(V, C)는 `SecureBuffer`에 보관되어 `Drop` 시 자동 소거됩니다. `CtrDRBGRng`(AES-256-CTR 기반)는 향후 AES-256 구현 완료 후 제공 예정입니다.

### ML-KEM.KeyGen (Algorithm 15, 19)

`MLKEM::key_gen`은 RNG로 32바이트 시드 $d$와 $z$를 생성한 뒤 `key_gen_internal`에 위임합니다. 내부적으로 K-PKE 키 생성을 수행하고, 역캡슐화 키를 $\text{dk}_{\text{PKE}} \| \text{ek} \| H(\text{ek}) \| z$ 형태로 조립하여 `SecureBuffer`에 보관합니다. 캡슐화 키 직렬화 검증 시 $H(\text{ek})$를 내장하여 역직렬화 시점에 무결성을 검증할 수 있도록 합니다.

### ML-KEM.Encaps (Algorithm 17, 20)

`MLKEM::encaps`는 RNG로 32바이트 난수 $m$을 생성하고, $(K, r) = G(m \| H(\text{ek}))$로 공유 비밀 $K$와 암호화 난수 $r$을 결정론적으로 유도합니다. $r$을 사용하여 K-PKE.Encrypt를 수행하고, 공유 비밀 $K$를 `SecureBuffer`에 담아 암호문과 함께 반환합니다.

### ML-KEM.Decaps (Algorithm 18, 21)

`MLKEM::decaps`는 FO 변환의 핵심인 암묵적 거부(implicit rejection)를 구현합니다. 역캡슐화 키 $\text{dk}$에서 $\text{dk}_{\text{PKE}}$, $\text{ek}$, $H(\text{ek})$, $z$를 추출한 뒤:

1. $`m' = \text{K-PKE.Decrypt}(\text{dk}_{\text{PKE}}, c)`$
2. $`(K', r') = G(m' \| H(\text{ek}))`$
3. $`\bar{K} = J(z \| c)`$
4. $`c' = \text{K-PKE.Encrypt}(\text{ek}, m', r')`$
5. $`K = \begin{cases} K' & \text{if } c = c' \\ \bar{K} & \text{otherwise} \end{cases}`$

단계 5의 암호문 비교($c = c'$)는 `entlib-native-constant-time`의 `ConstantTimeEq` 트레이트로, 공유 비밀 선택($K'$ vs $\bar{K}$)은 `ConstantTimeSelect` 트레이트로 수행됩니다. 이로써 변조된 암호문에 대해서도 실행 시간이 일정하게 유지되어 타이밍 부채널(timing side-channel) 공격을 차단합니다.

### 캡슐화 키 검증

`MLKEMEncapsulationKey::from_bytes`는 FIPS 203 모듈러스 검사를 수행합니다. $\text{ek}[0..384k]$ 구간의 모든 12-bit 계수가 $q$ 미만인지 확인하며, 위반 시 `InvalidEncapsulationKey` 오류를 반환합니다. `MLKEMDecapsulationKey::from_bytes`는 내장된 $H(\text{ek})$ 해시를 재계산하여 역캡슐화 키의 무결성을 검증합니다.

## 오류 처리: `error` 모듈

`MLKEMError` 열거형은 다섯 가지 오류 유형을 정의합니다:
- `InvalidLength`: 입력 바이트열 길이 불일치
- `InternalError`: 내부 연산 실패 (SHA3, SecureBuffer 등)
- `RngError`: 난수 생성기 오류 (reseed 필요 등)
- `InvalidEncapsulationKey`: 캡슐화 키 모듈러스 검사 실패
- `InvalidDecapsulationKey`: 역캡슐화 키 해시 검증 실패

## 피처 플래그

본 크레이트는 의존 크레이트(`entlib-native-secure-buffer`, `entlib-native-sha3`)의 `std` 피처를 통해 표준 라이브러리 지원을 제어합니다. `std` 활성화 시 OS 메모리 잠금(`mlock`), 런타임 페이지 크기 조회, `explicit_bzero` 폴백이 사용되며, 비활성화 시 `no_std` 환경에서 동작합니다.
