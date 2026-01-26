# 얽힘 라이브러리: 네이티브 브릿지

[Rust의 소유권 개념](https://doc.rust-kr.org/ch04-00-understanding-ownership.html)은 저의 흥미를 유발하는 데 완벽하게 성공했고, 복합적인 Rust만의 특색있는 개발 방법(컴파일러의 메모리 안정성, 하드웨어 수준의 제어 등...)을 통해 [얽힘 라이브러리](https://github.com/Quant-Off/entanglementlib)를 안전하게 구현하는 데 목표를 두고자 했습니다.

이 Rust 네이티브 브릿지 모듈은 [얽힘 라이브러리의 BC low-level API 브랜치](https://github.com/Quant-Off/entanglementlib/tree/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto)에서 첫 구현된 `Project Panama API` 기반 네이티브 키 관리 기능([`EntLibCryptoKey.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto/key/EntLibCryptoKey.java))을 강화하기 위해 마련됐습니다. 세부적으로 파고 들어가면 키가 소거되는 로직 전반도 변경 소요가 큽니다. 아니 확실하게 변경 될 겁니다([`KeyDestroyHelper.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/security/KeyDestroyHelper.java)와 같은 꽤 난잡한 클래스 등).

얽힘 라이브러리 내에서 [Linker API (JEP389)](https://openjdk.org/jeps/389)를 사용하여 구현됩니다. 이 모듈은 전통적 방법이지만 어렵고 불안정한 JNI(Java Native Interface)로 네이티브 메소드 호출 작업을 수행하는 것을 넘어 코드와 데이터 복사 오버헤드 없이 Java와 Rust가 동일한 메모리 주소를 공유할 수 있도록 돕습니다.

Rust 코드는 [Cargo.toml](Cargo.toml)를 보면 알 수 있듯 모듈은 빌드 시 `.so`, `.dll`, `.dylib` 으로 안전하게 빌드될 수 있도록 `C-ABI` 라이브러리로 빌드됩니다.

> 이 모듈은 얽힘 라이브러리 `1.1.0` 버전이 공개되기 전에 만들어졌습니다. 차라리 `2.0.0` 으로의 점프를 고려해보기도 했지만 지금까지 발생한 커밋과 저만의 버전 관리 신념을 명확히 하기 위해 그렇게 하진 않았습니다...

모든 기능이 수학적으로 안전한 연산을 거치고 있다는 것을 증명하기 위해 최대한 안정화한 다음 `Hex` 및 `F*`를 사용하여 형식적인 검증을 수행하려고 합니다. 사실, 안정화된 이후에는 어떠한 테스트든 모두 받아 완벽한 검증을 받아내는 것이 목표입니다.

## 이 모듈이 개발되기 전 생각한 아이디어

제가 이 모듈을 만들면서 구현하고 싶은 세 가지의 주요 기능이 있습니다.

1. 컴파일러 최적화 방지형의 '보안 제거'
2. 키 마스킹 및 '얽힘' 로직
3. 양자-내성 암호화 '프리미티브 네이티브 가속'

이름만 보면 꽤 복잡해 보일 수 있습니다만, 생각보다 직관적입니다.

### 1번 아이디어

단순하게도 Rust의 `zeroize` 크레이트를 사용하여 메모리 소거가 생략되지 않음을 보장하는 `volatile` 쓰기 로직을 구현하고자 했습니다. 이 과정은 수학적으로 간단하게 표현되기도 합니다. 소거 후 메모리 상태 $M$이 모든 주소 $`i`$에 대해 $`M[i] = 0`$임을 보장합니다. 사이트 채널(side channel) 공격자가 잔류 자기(remanence)를 통해 데이터를 복원할 확률 $` P(\text{recovery}) `$를 $` 0 `$에 수렴하게 만듭니다.

### 2번 아이디어

Rust가 `MemorySegment` 주소를 받으면 내부에서 임의의 난수 마스크 $M$을 생성하여 실제 키 $K$를 다음과 같이 변환하여 저장하니다.

$$
K_{\text{stored}} = K_{\text{raw}} \oplus M
$$

이는 보안 관점에서 '메모리 덤프 공격이 발생하더라도 공격자는 마스크 $M$ 없이는 원본 키를 복구할 수 없다'와 같이 해석할 수도 있습니다. $M$은 Rust의 스택 영역이나 별도의 보안 메모리 구역에 격리하여 시야 밖으로 나가지 않게 관리됩니다. 얽힘(entanglement)이라는 양자물리학적 의의와 상당히 맞닿아있다고 생각됩니다.

### 3번 아이디어

이 아이디어는 꽤 반항적으로 보일 수 있습니다. `BouncyCastle` 의존성을 탈피하기 위한 아이디어입니다. 역설적으로 '매력'으로 작용하기도 합니다.

이 아이디어는 이 모듈의 전체 기능에서도 핵심적으로 작용합니다. 왜냐하면 얽힘 라이브러리는 `BC low-level API`에 상당히 의존적이거든요. 그러니까, 저는 시스템 조각들이 각자 위치에서 꼭 필요한 의존성만 소극적으로 사용하기를 원합니다.

Java에서 전달한 `MemorySegmenet` 포인터를 직접 참조하여 복사 오버헤드 없이 Rust의 SIMD(Single Instruction Multiple Data) 명령어를 통해 양자-내성 암호화 연산을 수행합니다. 아무래도 이 전반적인 과정엔 [`pqcrypto`](https://github.com/rustpq/pqcrypto)같은 크레이트를 사용하면 될 것 같습니다.

연산 효율성은 제미나이를 사용하면 다음과 같이 정의됩니다.

$$
\eta = \frac{T_{\text{total}}}{T_{\text{compute}} + T_{\text{copy}}}
$$

`Linker API`를 통한 Rust 직접 접근은 $T_{\text{copy}}$를 $0$으로 만든다고 합니다. 음... 중요한 건 아무래도 직접 해봐야 알 것 같습니다.

### 아이디어에 따른 컨셉슈얼 구현 예시

다음은 Rust 측에서 Java의 `MemorySegment` 주소를 받아 안전히 처리하는 인터페이스 구조입니다.

```rust
use zeroize::Zeroize;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entanglement_secure_wipe(ptr: *mut u8, len: usize) {
    // Java의 MemorySegment 주소로부터 슬라이스 생성
    let data = std::slice::from_raw_parts_mut(ptr, len);
    
    // 컴파일러가 삭제하지 못하도록 보장된 소거 수행
    data.zeroize();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn entanglement_mask_key(ptr: *mut u8, len: usize, mask_ptr: *const u8) {
    let key = std::slice::from_raw_parts_mut(ptr, len);
    let mask = std::slice::from_raw_parts(mask_ptr, len);
    
    for i in 0..len {
        key[i] ^= mask[i]; // XOR을 통한 데이터 '얽힘' 처리
    }
}
```

벌써부터 `Unsafe` 경고가 두려워지는 코드입니다.

## 구현

가장 간단한 [1번 아이디어](#1번-아이디어)부터 구현했습니다. 이 구현의 핵심은 Rust의 `zeroize` 크레이트를 사용하여 컴파일러가

> "어차피 메모리 해제될 건데 0으로 채우는 과정 불필요함"

이라고 판단해 코드를 삭제하는 것을 막는 것입니다.

해당 기능의 구현은 [`modules/secure_wipe.rc`](https://github.com/Quant-Off/entlib-native/tree/main/src/modules/secure_wipe.rs) 파일에서 구현됩니다. 이제 위에서 제시한 아이디어에 대한 기능과 파생된 기능에 대해 `modules` 디렉토리 하위에서 작업하기로 약속합니다.