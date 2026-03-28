# ML-DSA 크레이트 (entlib-native-mldsa)

> Q. T. Felix (수정: 26.03.24 UTC+9)
> 
> [English README](README_EN.md)

`entlib-native-mldsa`는 NIST FIPS 204에 규정된 모듈 격자 기반 전자 서명 알고리즘(Module Lattice-based Digital Signature Algorithm, ML-DSA)의 순수 Rust 구현체입니다. 본 크레이트는 세 가지 파라미터 셋(ML-DSA-44/65/87)을 지원하며, 비밀 키 메모리 보호, 헤지드 서명, 상수-시간 필드 연산을 통해 부채널 공격을 방어합니다.

## 보안 위협 모델

RSA 및 ECDSA와 같은 기존 전자 서명 알고리즘은 Shor 알고리즘을 구현한 양자 컴퓨터에 의해 다항식 시간 내 파훼됩니다. ML-DSA는 모듈 격자 위의 Learning With Errors(LWE) 문제와 Short Integer Solution(SIS) 문제의 계산적 난해성에 안전성을 근거하며, 현재 알려진 양자 알고리즘으로도 지수 시간이 소요됩니다.

구현 수준의 공격 표면은 세 가지입니다. 첫째, 비밀 키 메모리 노출: `s1`, `s2`, `t0`, `K_seed`, `tr` 등 비밀 성분이 스왑 파일이나 코어 덤프에 유출될 수 있습니다. 이를 `SecureBuffer`(OS `mlock` + Drop 시 자동 소거)로 방어합니다. 둘째, 서명 시 타이밍 부채널: 비밀 성분에 의존하는 분기가 서명 키를 노출할 수 있습니다. 유한체 연산(`Fq::add`, `Fq::sub`, `power2round` 등)은 `entlib-native-constant-time`의 상수-시간 선택 연산으로 구현됩니다. 셋째, nonce 재사용: 동일한 `rnd`로 두 개의 서명을 생성하면 비밀 키가 복원됩니다. 헤지드(Hedged) 서명 모드(`rnd ← RNG`)로 이를 완전히 방지합니다.

## 파라미터 셋

NIST FIPS 204 Section 4에 정의된 세 가지 파라미터 셋을 지원합니다.

| 파라미터 셋    |  NIST 보안 카테고리  |  pk 크기 |  sk 크기 |  서명 크기 | λ (충돌 강도) |
|-----------|:--------------:|-------:|-------:|-------:|:---------:|
| ML-DSA-44 | 2 (AES-128 동급) | 1312 B | 2560 B | 2420 B |  128-bit  |
| ML-DSA-65 | 3 (AES-192 동급) | 1952 B | 4032 B | 3309 B |  192-bit  |
| ML-DSA-87 | 5 (AES-256 동급) | 2592 B | 4896 B | 4627 B |  256-bit  |

각 파라미터 셋은 행렬 차원 $(k, l)$, 비밀 계수 범위 $\eta$, 챌린지 다항식 가중치 $\tau$, 마스킹 범위 $\gamma_1$, 분해 범위 $\gamma_2$, 힌트 최대 가중치 $\omega$를 달리합니다. 컴파일 타임 const 제네릭으로 단형화(monomorphization)되어 런타임 오버헤드가 없습니다.

## 공개 API

### `MLDSA` 구조체: Algorithm 1–3

`MLDSA`는 정적 메소드만 제공하는 진입점입니다. 파라미터 셋 정보는 키 타입에 내장되므로 서명·검증 시 별도로 지정하지 않습니다.

```rust
// Algorithm 1: ML-DSA.KeyGen
let mut rng = HashDRBGRng::new_from_os(None).unwrap();
let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).unwrap();

// Algorithm 2: ML-DSA.Sign (헤지드 — rnd ← RNG)
let sig = MLDSA::sign(&sk, message, ctx, &mut rng).unwrap();

// Algorithm 3: ML-DSA.Verify
let ok = MLDSA::verify(&pk, message, &sig, ctx).unwrap();
assert!(ok);
```

**메시지 전처리**: 외부 인터페이스는 FIPS 204 Section 5.2에 따라 $M' = \texttt{0x00} \| \text{IntegerToBytes}(|ctx|, 1) \| ctx \| M$ 을 구성하여 내부 알고리즘에 전달합니다. `ctx.len() > 255` 이면 `ContextTooLong`을 반환합니다.

**헤지드 서명**: `sign`은 32바이트 `rnd`를 RNG에서 생성하여 내부 알고리즘에 전달합니다. `rnd`가 공개되더라도 결정론적 서명이 되지 않으므로 nonce 재사용 공격이 불가능합니다.

### `MLDSAParameter` 열거형

```rust
pub enum MLDSAParameter { MLDSA44, MLDSA65, MLDSA87 }
```

`pk_len()`, `sk_len()`, `sig_len()`은 `const fn`으로 제공됩니다.

## 키 타입

### `MLDSAPublicKey`

인코딩된 공개 키 바이트($`\rho \| \text{SimpleBitPack}(t_1, 10)`$)와 파라미터 셋을 보유합니다. `from_bytes`로 외부 바이트열에서 복원할 수 있으며, 길이 불일치 시 `InvalidLength`를 반환합니다.

> [!NOTE]
> **pkEncode 레이아웃**: $\rho$ (32 B) $\|$ SimpleBitPack$`(t_1[0], 10)`$ $\|$ $\cdots$ $\|$ SimpleBitPack$`(t_1[k-1], 10)`$
>
> $t_1$ 계수는 10비트씩 패킹되어 다항식당 320 B, 전체 $32 + 320k$ B입니다.

### `MLDSAPrivateKey`

비밀 키 바이트를 `SecureBuffer`(OS `mlock`)에 보관합니다. `Drop` 시 메모리가 즉시 소거(Zeroize)됩니다. `as_bytes()`로 슬라이스를 참조할 수 있으나, 파일 저장 시 반드시 PKCS#8 암호화를 적용해야 합니다.

> [!NOTE]
> **skEncode 레이아웃**: $\rho$ (32 B) $\|$ $K_{\text{seed}}$ (32 B) $\|$ $tr$ (64 B) $\|$ BitPack$`(s_1, \eta, \eta)`$ $\|$ BitPack$`(s_2, \eta, \eta)`$ $\|$ BitPack$`(t_0, 4095, 4096)`$
>
> $\eta = 2$이면 계수당 3비트, $\eta = 4$이면 4비트로 인코딩됩니다.

## RNG 추상화

### `MLDSARng` 트레이트

```rust
pub trait MLDSARng {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLDSAError>;
}
```

구현체는 NIST SP 800-90A Rev.1 이상의 보안 강도(≥ 256-bit)를 제공하는 DRBG여야 합니다.

### `HashDRBGRng`

NIST Hash_DRBG (SHA-512 기반, Security Strength 256-bit) 래퍼입니다. `new_from_os`가 유일한 초기화 경로이며, OS 엔트로피 소스(`getrandom`/`getentropy`)만 허용됩니다. 내부 상태 V, C는 `SecureBuffer`에 보관되어 Drop 시 자동 소거됩니다. `MLDSAError::RngError(ReseedRequired)` 수신 시 `reseed()`를 호출해야 합니다.

### `CtrDRBGRng`

AES-256-CTR 기반 CTR_DRBG 예약 구조체입니다. `entlib-native-aes` 완료 전까지 모든 메소드가 `NotImplemented`를 반환합니다.

## 내부 알고리즘 구조

### 키 생성 (Algorithm 4/6)

$\xi \in \mathbb{B}^{32}$ 시드로부터 SHAKE256 확장으로 $(\rho, \rho', K_{\text{seed}})$를 유도합니다.

$$A_{\hat{}} \leftarrow \text{ExpandA}(\rho), \quad (s_1, s_2) \leftarrow \text{ExpandS}(\rho')$$

$$t = \text{INTT}(A_{\hat{}} \circ \text{NTT}(s_1)) + s_2, \quad (t_1, t_0) \leftarrow \text{Power2Round}(t, d)$$

Power2Round는 $a_1 = \lceil a / 2^{13} \rceil$, $a_0 = a - a_1 \cdot 2^{13}$ 으로 분할하며, 음수 $a_0$의 $\mathbb{Z}_q$ 표현 변환에 `ct_is_negative` + `ct_select`를 사용합니다.

트레이스 $tr = H(\text{pkEncode}(\rho, t_1), 64)$는 SHAKE256 증분 해싱으로 계산됩니다.

### 서명 (Algorithm 5)

거절 샘플링 기반 반복 루프입니다. 각 시도에서:

$$y \leftarrow \text{ExpandMask}(\rho'', \kappa), \quad w = \text{INTT}(A_{\hat{}} \circ \text{NTT}(y))$$

$$w_1 = \text{HighBits}(w, 2\gamma_2), \quad \tilde{c} \leftarrow H(\mu \| w_1, \lambda/4)$$

$$z = y + c \cdot s_1$$

$`\|z\|_\infty \ge \gamma_1 - \beta`$ 이거나 $`\|\text{LowBits}(w - c \cdot s_2, 2\gamma_2)\|_\infty \ge \gamma_2 - \beta`$ 이면 거절하고 재시도합니다. 힌트 $h = \text{MakeHint}(-c \cdot t_0, w - c \cdot s_2 + c \cdot t_0, 2\gamma_2)$를 생성하고, $\|h\|_1 \le \omega$를 확인합니다. 최대 시도 횟수 초과 시 `SigningFailed`를 반환합니다.

### 검증 (Algorithm 7)

$\|z\|_\infty \ge \gamma_1 - \beta$ 또는 $\|h\|_1 > \omega$ 이면 즉시 `false`를 반환합니다.

$$w_1' = \text{UseHint}(h, \text{INTT}(A_{\hat{}} \circ \text{NTT}(z)) - c \cdot t_1 \cdot 2^d, 2\gamma_2)$$

$\tilde{c}$와 재구성된 $H(\mu \| w_1', \lambda/4)$를 비교합니다.

> [!NOTE]
> **상수-시간 챌린지 비교**: 서명 유효성을 결정하는 챌린지 해시 비교(`c_tilde` ↔ 재계산값)는 비밀 데이터가 아니므로 표준 바이트 비교를 사용합니다. 노름 검사(`fq_to_signed`)도 서명 재시도 여부를 결정하는 공개 데이터이므로 동일하게 타이밍-가변 경로를 허용합니다.

### NTT / 유한체 연산

다항식 환 $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, $q = 8{,}380{,}417$ 위에서 동작합니다. NTT는 비트 반전 순서의 몽고메리 도메인 원시 단위근 배열(`ZETAS[256]`)을 사용합니다. 몽고메리 환원 상수는 $q^{-1} \bmod 2^{32} = 58{,}728{,}449$이며, INTT 정규화 상수는 $N^{-1} \cdot R^2 \bmod q = 41{,}978$입니다.

`Fq::add`, `Fq::sub`는 분기 없는 상수-시간 구현(`ct_is_negative` + `ct_select`)을 사용합니다.

## 오류 타입

| 오류 | 의미 |
|------|------|
| `InvalidLength` | 키 또는 서명 바이트 길이 불일치 |
| `InternalError` | 해시 함수 오류, 메모리 할당 실패 |
| `RngError` | RNG 내부 오류 또는 reseed 필요 |
| `ContextTooLong` | ctx가 255바이트 초과 |
| `SigningFailed` | 거절 샘플링 최대 반복 초과 (극히 희박) |
| `InvalidSignature` | 서명 검증 실패 |
| `NotImplemented` | CTR_DRBG 등 미구현 기능 |
