# AES-256 크레이트 (entlib-native-aes)

> Q. T. Felix (수정: 26.03.22 UTC+9)
>
> [English README](README_EN.md)

`entlib-native-aes`는 NIST FIPS 140-3 및 Common Criteria EAL4+ 인증 요구사항을 충족하도록 설계된 AES-256 암호화 모듈입니다. **256비트 키만 지원**하며, 기밀성과 무결성을 동시에 제공하는 두 가지 승인된 운용 모드를 구현합니다.

- **AES-256-GCM** — NIST SP 800-38D 준거 AEAD (Authenticated Encryption with Associated Data)
- **AES-256-CBC-HMAC-SHA256** — NIST SP 800-38A + Encrypt-then-MAC 구성 (CBC 단독 사용 금지)

**이 알고리즘은 128, 192 키 길이는 의도적으로 대응하지 않습니다.** FIPS 140-3은 AES-256 사용을 권고하며, 단일 키 크기만 노출하여 잘못된 키 길이 선택으로 인한 보안 약화를 사전에 차단합니다.

## 보안 위협 모델

### 캐시 타이밍 공격 (Cache-Timing Attack)

AES의 표준 소프트웨어 구현은 SubBytes 연산을 위해 256바이트 SBox 룩업 테이블을 사용합니다. 이 접근 방식은 치명적인 취약점을 내포합니다. 공격자가 동일한 CPU 캐시를 공유하는 환경(VPS, 클라우드)에서 캐시 히트·미스 패턴으로부터 접근된 테이블 인덱스, 즉 비밀 키 바이트를 통계적으로 복원할 수 있습니다. 다니엘 번스타인(D. J. Bernsteint)의 2005년 AES 타이밍 공격은 이를 실증적으로 증명하였습니다.

본 크레이트는 룩업 테이블을 일체 사용하지 않습니다. SubBytes는 GF(2^8) 역원 계산과 아핀 변환을 순수 산술 비트 연산으로 수행하며, 모든 연산의 실행 시간은 비밀 키 및 평문 값과 완전히 독립적입니다.

### 패딩 오라클 공격 (Padding Oracle Attack)

CBC 모드에서 복호화 오류 응답이 패딩 유효성에 따라 달라지면, 공격자는 적응적 선택 암호문 공격(ACCA)으로 임의 암호문을 완전히 복호화할 수 있습니다(POODLE, Lucky 13 변종). 본 구현은 **Encrypt-then-MAC** 구성을 강제하여 이 공격 벡터를 원천 차단합니다. MAC 검증이 선행되며, MAC 실패 시 복호화 연산 자체를 수행하지 않습니다.

### GCM Nonce 재사용 (Nonce Reuse)

GCM에서 동일한 (키, nonce) 쌍이 두 번이라도 사용되면 두 암호문의 XOR로부터 평문의 XOR이 노출되어 기밀성이 완전히 붕괴됩니다. 나아가 GHASH 다항식 방정식 풀기를 통해 인증 키 H가 복원되어 무결성도 위협받습니다. 본 크레이트는 nonce 생성 정책을 호출자에 위임하며, API 문서에 명시적 경고를 부착합니다. 프로덕션 환경에서는 `entlib-native-rng`의 `HashDRBGSHA256`로 nonce를 생성하거나, 충돌 없음이 보장된 카운터 기반 구성을 사용하십시오.

## 보안 핵심: 상수-시간 AES 코어

### GF(2^8) 산술

AES SubBytes는 유한체 GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1) 위의 역원을 계산한 후 아핀 변환(Affine Transformation)을 적용합니다.

#### xtime: GF(2^8) 에서 x 를 곱함

$$ \text{xtime}(a) = \begin{cases} a \ll 1 & \text{if MSB}(a) = 0 \\ (a \ll 1) \oplus \texttt{0x1b} & \text{if MSB}(a) = 1 \end{cases} $$

분기문 없이 구현합니다.

$$\text{mask} = -(a \gg 7), \quad \text{xtime}(a) = (a \ll 1) \oplus (\texttt{0x1b} \land \text{mask})$$

`mask`는 MSB가 1이면 `0xFF`, 0이면 `0x00`이므로, 단일 `SHR`, `NEG`, `AND`, `XOR` 명령어 4개로 컴파일됩니다.

#### gmul: GF(2^8) 곱셈 — 고정 8회 반복

$$\text{gmul}(a, b) = \bigoplus_{i=0}^{7} \left( a \cdot x^i \land -(b_i) \right)$$

여기서 $b_i$는 $b$의 $i$번째 비트입니다. `-(b & 1).wrapping_neg()`로 비트를 마스크로 변환하여 분기 없이 조건부 XOR를 수행합니다. 반복 횟수는 비밀 데이터와 무관한 고정 값 8이므로 타이밍이 일정합니다.

#### gf_inv: GF(2^8) 역원 — 페르마의 소정리

유한체에서 $a \ne 0$이면 $a^{-1} = a^{2^8 - 2} = a^{254}$입니다. $a = 0$이면 $0^{254} = 0$이 자연히 반환되므로 분기가 필요하지 않습니다.

> [!NOTE]
> **Square-and-Multiply 전개**: $254 = \texttt{11111110}_2$이므로
>
> $$a^{254} = a^{128} \cdot a^{64} \cdot a^{32} \cdot a^{16} \cdot a^8 \cdot a^4 \cdot a^2$$
>
> 7번의 제곱(squaring)과 6번의 곱셈으로 총 13회의 `gmul` 호출로 계산됩니다. 테이블 접근이 전혀 없으므로 캐시 타이밍 채널이 존재하지 않습니다.

#### sub_byte: SubBytes 아핀 변환

역원 $a^{-1}$에 아핀 변환 $M \cdot a^{-1} + c$를 적용합니다.

$$b_i = a^{-1}_i \oplus a^{-1}_{(i+4) \bmod 8} \oplus a^{-1}_{(i+5) \bmod 8} \oplus a^{-1}_{(i+6) \bmod 8} \oplus a^{-1}_{(i+7) \bmod 8} \oplus c_i$$

비트 회전으로 동치 표현합니다 ($c = \texttt{0x63}$).

```math
\text{sub\_byte}(a) = a^{-1} \oplus \text{ROL}(a^{-1}, 1) \oplus \text{ROL}(a^{-1}, 2) \oplus \text{ROL}(a^{-1}, 3) \oplus \text{ROL}(a^{-1}, 4) \oplus \texttt{0x63}
```

역 SubBytes (`inv_sub_byte`)는 역 아핀 변환 후 역원을 계산합니다.

```math
\text{inv\_sub\_byte}(a) = \text{gf\_inv}\!\left(\text{ROL}(a,1) \oplus \text{ROL}(a,3) \oplus \text{ROL}(a,6) \oplus \texttt{0x05}\right)
```

### 키 스케줄 (Key Schedule)

AES-256은 32바이트 마스터 키로부터 15개의 라운드 키(각 16바이트)를 생성합니다. 키 확장에 사용되는 중간 배열 `w: [u32; 60]`은 라운드 키 추출 직후 `write_volatile`로 소거됩니다. `KeySchedule` 구조체는 `Drop` 트레이트를 구현하여, 스코프 이탈 시 240바이트 라운드 키 전체를 자동으로 강제 소거합니다.

```rust
impl Drop for KeySchedule {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            for b in rk {
                unsafe { write_volatile(b, 0) };
            }
        }
    }
}
```

## AES-256-GCM

NIST SP 800-38D §7.1에 따른 구현입니다. 96비트(12 bytes) nonce만 지원합니다. 임의 길이의 IV를 허용하는 일반화 경로(GHASH를 이용한 IV 파생)는 nonce 충돌 위험을 증가시키므로 의도적으로 제외하였습니다.

### 내부 동작

1. **해시 부키 생성**
   - $`H = E_K(0^{128})`$
2. **초기 카운터 블록**
   - $`J_0 = \text{nonce}_{96} \| \texttt{0x00000001}_{32}`$
3. **암호화 (GCTR)**
   - $`C = \text{GCTR}_K(\text{inc}_{32}(J_0),\ P)`$
   - $`\text{inc}_{32}`$는 하위 32비트를 빅엔디안으로 1 증가시킵니다.
4. **인증 태그**
   - $`T = E_K(J_0) \oplus \text{GHASH}_H(A,\ C)`$

여기서 GHASH는 AAD, 암호문, 길이 블록 $`[\text{len}(A)]_{64} \| [\text{len}(C)]_{64}`$를 순서대로 처리합니다.

### GHASH: GF(2^128) 곱셈 — 상수-시간 보장

GCM 인증은 $\text{GF}(2^{128})$ 위에서 이루어집니다. 환원 다항식은 $f(x) = x^{128} + x^7 + x^2 + x + 1$이며, 이는 비트열 `0xE1000...0` (128비트, MSB 우선)으로 표현됩니다.

> [!NOTE]
> **상수-시간 GF(2^128) 곱셈**: NIST SP 800-38D Algorithm 1의 표준 구현은 비밀 값에 의존하는 조건 분기를 포함합니다. 본 구현은 고정 128회 반복과 비트 마스크 트릭으로 이를 제거합니다.
>
> 각 반복에서 $X$의 $i$번째 비트 $X_i$를 마스크로 변환하여 분기 없이 누산합니다.
>
> $$\text{mask} = -(X_i), \quad Z \mathrel{⊕}= V \land \text{mask}$$
>
> $V$의 우측 시프트 후 조건부 환원도 동일한 방식으로 처리됩니다.
>
> ```math
> \text{lsb\_mask} = -(V_{127}), \quad V_{\text{high}} \mathrel{⊕}= \texttt{0xE100...00} \land \text{lsb\_mask}
> ```

`GHashState`는 `Drop` 트레이트를 구현하여, 내부 상태 $Z$와 해시 부키 $H$를 `write_volatile`로 소거합니다.

### 복호화 검증 원칙

복호화 시 태그를 먼저 재계산하고, `ConstantTimeEq::ct_eq()`를 사용하여 16바이트를 상수-시간으로 비교합니다. 검증에 실패하면 `AESError::AuthenticationFailed`를 반환하고 평문 출력을 일체 수행하지 않습니다.

```rust
// 상수-시간 16바이트 비교
let mut r = 0xFFu8;
for i in 0..16 {
r &= expected_tag[i].ct_eq(&received_tag[i]).unwrap_u8();
}
if r != 0xFF { return Err(AESError::AuthenticationFailed); }
// 검증 통과 후에만 복호화 수행
```

### API

```rust
AES256GCM::encrypt(
key: &SecureBuffer,           // 256비트 AES 키
nonce: &[u8; 12],             // 96비트 nonce (반드시 유일해야 함)
aad: &[u8],                   // 추가 인증 데이터
plaintext: &[u8],
ciphertext_out: &mut [u8],    // plaintext.len() bytes
tag_out: &mut [u8; 16],       // 인증 태그 출력
) -> Result<(), AESError>

AES256GCM::decrypt(
key: &SecureBuffer,
nonce: &[u8; 12],
aad: &[u8],
ciphertext: &[u8],
tag: &[u8; 16],               // 수신한 인증 태그
plaintext_out: &mut [u8],     // ciphertext.len() bytes
) -> Result<(), AESError>         // 태그 불일치 시 AuthenticationFailed
```

> [!WARNING]
> 동일한 `(key, nonce)` 쌍을 두 번 이상 사용하면 기밀성과 무결성이 모두 파괴됩니다. nonce는 `entlib-native-rng`의 `HashDRBGSHA256`를 통해 생성하거나, 단조 증가 카운터로 관리하십시오.

## AES-256-CBC-HMAC-SHA256

NIST SP 800-38A의 CBC 모드 단독 사용은 기밀성만 보장하고 무결성을 제공하지 않습니다. 본 구현은 **Encrypt-then-MAC** 구성을 강제합니다. 암호화 후 `IV || 암호문`에 HMAC-SHA256 태그를 생성하여 출력에 부착합니다.

### 출력 형식

```
┌─────────────────┬────────────────────────────────────────┬───────────────────────────────┐
│   IV  (16 B)    │  Ciphertext + PKCS7 Padding  (N×16 B)  │  HMAC-SHA256(IV||CT)  (32 B)  │
└─────────────────┴────────────────────────────────────────┴───────────────────────────────┘
```

PKCS7 패딩은 항상 추가됩니다. 평문이 블록 경계에 정확히 맞아도 16바이트(`0x10` × 16)의 완전한 패딩 블록이 추가되므로, 출력 암호문의 길이는 항상 $`\lceil P / 16 \rceil + 1`$블록입니다.

> [!NOTE]
> **PKCS7 상수-시간 검증**: 복호화 시 패딩 바이트 검증은 XOR와 비트 마스크로 수행합니다.
>
> ```math
> \begin{align}
>     \text{diff}_i &= \text{data}[i] \oplus \text{pad\_byte}, \quad \text{not\_zero}_i = \frac{\text{diff}_i \mathbin{|} (-\text{diff}_i)}{2^7} \\
>     \text{valid} &= \bigwedge_{i} \overline{(\text{not\_zero}_i - 1)} \quad (\text{0xFF이면 유효})
> \end{align}
>```
>
> MAC 검증 통과 후에만 패딩 검증이 수행되므로, 공격자가 유효한 MAC 없이 패딩 오라클을 이용하는 것은 불가능합니다.

### 복호화 순서

1. 입력 형식 검증 (최소 64바이트, 블록 크기 정렬)
2. HMAC-SHA256 재계산 → `ct_eq_32`로 상수-시간 비교 (`AESError::AuthenticationFailed` 또는 통과)
3. MAC 검증 통과 후에만 AES-256-CBC 복호화 수행
4. PKCS7 패딩 검증 및 제거

### API

```rust
AES256CBCHmac::encrypt(
    enc_key: &SecureBuffer,   // 256비트 AES 암호화 키
    mac_key: &SecureBuffer,   // HMAC-SHA256 키 (최소 14 bytes, 권장 32 bytes)
    iv: &[u8; 16],            // 128비트 IV (메시지마다 고유해야 함)
    plaintext: &[u8],
    output: &mut [u8],        // 최소 cbc_output_len(plaintext.len()) bytes
) -> Result<usize, AESError>  // 출력에 쓰인 바이트 수

AES256CBCHmac::decrypt(
    enc_key: &SecureBuffer,
    mac_key: &SecureBuffer,
    input: &[u8],             // IV(16) || CT || HMAC(32) 형식
    output: &mut [u8],
) -> Result<usize, AESError>  // 복호화된 평문 바이트 수

// 버퍼 크기 계산 헬퍼
cbc_output_len(plaintext_len: usize) -> usize
cbc_plaintext_max_len(input_len: usize) -> Option<usize>
```

> [!IMPORTANT]
> `enc_key`와 `mac_key`는 반드시 독립적인 별개의 키를 사용해야 합니다. 동일한 키를 두 용도에 재사용하면 암호화 스킴의 안전성 증명이 무효가 됩니다. 키 파생이 필요한 경우 `entlib-native-hkdf`를 사용하여 마스터 키로부터 두 개의 독립적인 서브키를 파생하십시오.

## 키 관리 요구사항

| 파라미터      | 요구사항                         | 근거                          |
|-----------|------------------------------|-----------------------------|
| AES 키     | 정확히 256비트 (32 bytes)         | FIPS 140-3, NIST SP 800-38D |
| GCM nonce | 96비트 (12 bytes), 유일          | NIST SP 800-38D §8.2        |
| CBC IV    | 128비트 (16 bytes), 각 메시지마다 고유 | NIST SP 800-38A §6.2        |
| CBC MAC 키 | AES 키와 독립, 최소 112비트          | NIST SP 800-107r1           |

모든 키는 반드시 `entlib-native-secure-buffer`의 `SecureBuffer`로 관리하여 mlock 기반 메모리 잠금과 Drop 시 자동 소거를 보장해야 합니다.

## 검증

### NIST CAVP 테스트 벡터

| 테스트                | 출처                                    | 결과 |
|--------------------|---------------------------------------|----|
| AES-256 ECB 블록 암호화 | NIST FIPS 197 Appendix B              | O  |
| AES-256-GCM 암호화    | NIST CAVP (OpenSSL 교차 검증)             | O  |
| AES-256-GCM 복호화    | 역방향 라운드트립                             | O  |
| AES-256-CBC 암호문    | NIST SP 800-38A F.2.5 (OpenSSL 교차 검증) | O  |
| GCM 태그 1비트 변조      | 조작된 태그 → `AuthenticationFailed`       | O  |
| CBC MAC 1비트 변조     | 조작된 MAC → `AuthenticationFailed`      | O  |

```bash
cargo test -p entlib-native-aes
```

> [!WARNING]
> KAT(Known Answer Test) 테스트 벡터를 엄밀하게 통과하기 위한 준비 중에 있습니다.
> 
> 위 표의 근거는 테스트 벡터의 개별 테스트 블럭의 일치 여부를 검증하는 테스트 모듈 `aes_test.rs`입니다.

## 설계 원칙 요약

1. **256비트 단일 키 강제** — 키 크기 선택 오류로 인한 보안 약화를 API 수준에서 차단합니다.
2. **룩업 테이블 완전 배제** — SBox를 포함한 모든 연산이 순수 산술 비트 연산으로 수행되어 캐시 타이밍 채널이 존재하지 않습니다.
3. **고정 반복 횟수** — `gmul`(8회), `gf128_mul`(128회) 등 모든 내부 루프는 비밀 데이터와 무관한 상수로 고정됩니다.
4. **Encrypt-then-MAC 강제** — CBC 단독 사용 API를 노출하지 않아 패딩 오라클 공격을 구조적으로 차단합니다.
5. **검증 후 복호화 원칙** — GCM 태그와 CBC HMAC 모두 상수-시간 검증 통과 전에 평문을 출력하지 않습니다.
6. **키 소재 즉시 소거** — `KeySchedule`, `GHashState`, 블록 연산 중간값 모두 `write_volatile`로 사용 직후 소거됩니다.
