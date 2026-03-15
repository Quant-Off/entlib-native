# 주체 간 상호 작용

얽힘 라이브러리는 Java 베이스(주체), 그 네이티브(entlib-native)는 Rust 베이스입니다. 이 문서에선 편의를 위해 이 두 주체를 통합하여 "얽힘 라이브러리 프로젝트(ELIB)", 개별적으로는 각각 Java, Rust로 언급하겠습니다.

ELIB에서 데이터의 생성은 다음 두 가지 케이스가 존재합니다.

- Rust 측 최초 생성
- Java 측 최초 생성

데이터가 선언된다면 반드시 "메모리를 할당한 주체가 메모리를 해제해야 한다." 라는 대원칙을 지켜야 합니다. 이를 고수하지 않으면 심각한 메모리 손상(Memory Corruption)이나 세그멘테이션 결함(Segmentation Fault)이 발생하여 시스템 전체의 안정성이 붕괴됩니다.

ELIB은 이러한 대원칙을 준수하면서도, Java, Rust 측에서 "내가 해제를 해야하는거였어?!" 라는 오해를 해결하기 위해 "통합 제어 아키텍처(Unified Control Architecture, UCA)"를 제공합니다.

## 통합 제어 아키텍처

UCA는 Java, Rust 각각에서 생성된(할당된) 데이터에 대해, 할당 해제(소유권) 여부를 해당 주체의 비즈니스 로직이 알 필요 없도록 하는 데 중점을 둡니다.

Rust는 ELIB 네이티브로써, FFI 경계 통신을 위해 소유권 플래그가 포함된 C-호환 구조체를 FFI 표준 규격으로 정의했습니다.

```rust
use entlib_native_ffi::FFIStandard; // 구조체
```

Rust가 최초로 데이터를 생성하는 경우를 Rust-Owned(RO) 패턴, 동일한 상황에 대해 Java도 똑같이 JO 패턴이라고 하겠습니다. 이 표준 구조체의 필드엔 `bool`타입의 `is_rust_owned` 가 존재합니다. 이 값이 `true`일 경우 RO 패턴이 적용되고, 그렇지 않으면 JO 패턴이 적용됩니다.

RO 패턴은 연산 수행 후 Rust 측 해제 전용 함수를 호출할 수 있습니다.

```rust
use entlib_native_secure_buffer::buffer::entlib_side_secure_free; // 함수
```

JO 패턴은 연산 수행 후 FFM API를 통해 `Arena#close()` 메소드를 사용하여 해제해야 합니다. 물론 이 기능은 직접 Raw하게 사용할 필요 없이 `SDCScopeContext` 객체를 사용할 수 있습니다.

ELIB은 이러한 방식으로 RO, JO 패턴의 파편화를 해결했습니다.

## RO 패턴을 통한 데이터 생성 시

그렇다면 RO 패턴을 통해 데이터가 생성되면 `FFIStandard` 구조체를 사용할 필요가 없을까요? 절대로 아닙니다.

RO 패턴은 Rust 측에서 최초로 데이터를 생성하는 경우입니다. 암호화 키나 난수 등 Rust에서 안전하게 생성된 이 데이터는 결국 Java 측 비즈니스 로직에서 사용되어야 합니다.

데이터 자체는 Rust의 메모리 공간에 `mlock`되어 있지만, Java가 이 데이터를 읽기 위해서는 원시 포인터와 길이를 전달받아야 합니다. 이때 Rust가 단순히 포인터만 던져주면, Java의 컨텍스트 객체는 이 메모리의 주인이 누구인지 알 방법이 없습니다.

따라서 Rust는 데이터를 생성한 직후 해당 포인터와 길이, 그리고 소유권 플래그를 `FFIStandard` 구조체에 담아 Java로 반환해야 합니다. 이 구조체 내의 `is_rust_owned` 값이 true로 설정되어 있어야만, Java 측 컨텍스트가 생명 주기를 추적하다가 스코프가 끝나는 시점에 올바르게 Rust 측 해제 전용 함수  `entlib_side_secure_free`를 호출할 수 있습니다.

Java는 `FFIStandard` 구조체를 전달받고 `ExternFFIStandard` 객체가 이를 래핑합니다. 스코프 종료 시 컨텍스트가 소유권 플래그를 확인하고 Rust 측 해제 함수 `entlib_side_secure_free`를 통해 소거 명령을 내립니다.

## FFIStandard vs SecureBuffer

내부 필드는 각각의 구조체가 동일한 연산을 취하는 것 처럼 보입니다만, 이 둘은 그 역할이 완전히 다릅니다.

Rust -> Java의 경우, Rust 로직이 안전한 `SecureBuffer` 내부에서 민감 데이터를 모두 생성합니다. 외부로 보낼 때가 되면, `SecureBuffer`가 파기(`Drop`)되지 않도록 소유권을 해제(`into_raw` 방식)하고, 그 알맹이(`ptr`, `len`)를 꺼내 `FFIStandard`에 담아 Java로 보냅니다.

반대로 Java -> Rust의 경우, Java 작업이 끝나고 파기 요청이 오면 Rust는 전달받은 `FFIStandard`의 `ptr`과 `len`을 다시 `SecureBuffer::from_raw_parts`로 감쌉니다. 감싸진 `SecureBuffer`가 함수 스코프를 종료하면서, 내장된 `Drop` 로직을 통해 완벽한 소거와 잠금 해제가 자동으로 수행되는 것입니다.

따라서 이 두 구조체는 서로를 대체하는 것이 아니라, 통신 시점에 서로의 형태로 변환(Transformation)되는 관계입니다.

## RO 및 JO 내부 로직 생명 주기

**RO 패턴**은 Rust가 주도적으로 보안 데이터를 생성하고, 소멸의 책임도 지는 구조입니다.

- 할당 (Rust): Rust 내부에서 메모리를 할당, 0으로 초기화, OS 메모리 락(lock)을 수행합니다.
- 전달 (Rust -> Java): Rust는 `SecureBuffer`가 소멸(`Drop`)되지 않도록 우회한 뒤, `ptr`, `len`, 그리고 `is_rust_owned = true` 플래그를 `FFIStandard` 구조체에 담아 Java로 반환합니다.
- 사용 (Java): Java의 `ExternFFIStandard`가 이를 래핑하여 비즈니스 로직에 사용합니다.
- 파기 요청 (Java -> Rust): Java의 스코프가 종료되면, 컨텍스트가 플래그를 확인하고 Rust 측 FFI 함수인 `entlib_side_secure_free`를 호출합니다.
- 소거 및 해제 (Rust): Rust는 전달받은 포인터를 다시 `SecureBuffer`로 감싸 스코프를 종료시킵니다. 이때 내장된 Drop 로직이 발동하여 물리적 소거, 잠금 해제, 메모리 할당 해제를 원자적으로 완수합니다.

**JO 패턴**은 Java가 민감 데이터 컨테이너(SDC) 객체인 `SensitiveDataContainer`(또는 `SDCScopeContext`)를 통해 데이터 공간을 선언하고, 물리적 소거 기능만 Rust의 강력한 제어력을 빌려 쓰는 구조입니다.

- 할당 (Java): SDC 내부에서 FFM API의 `Arena`를 통해 `off-heap` 메모리를 할당 및 선언, OS 메모리 락(lock)을 수행합니다.
- 사용 (Java <-> Rust): 필요한 경우 해당 포인터를 `FFIStandard(is_rust_owned = false)`를 통해 Rust로 보내 연산을 수행합니다.
- 소거 요청 (Java -> Rust): `try-with-resources` 스코프를 벗어나는 시점에 Java는 메모리를 즉시 해제하지 않고 Rust 측에 물리적 데이터 소거 로직 수행을 먼저 요청합니다.
- 최종 해제 (Java): Rust의 철저한 소거(`Zeroizer::zeroize_raw`)가 완료되었음을 확인한 후, Java 측 컨텍스트가 `Arena`를 닫아(`close()`) 최종적으로 메모리를 할당 해제합니다.

## 정리: 개별 패턴에 따른 상호 작용

이 장에서의 설명을 한꺼번에 정리하면 다음과 같습니다.

Java와 Rust 간의 데이터 통신은 소유권 플래그가 포함된 `FFIStandard` 구조체를 통해 이루어집니다. 이 구조체 내부의 `is_rust_owned` 값에 따라 메모리 해제의 책임 주체가 결정되며, 시스템은 RO 패턴과 JO 패턴으로 분기합니다.

### RO 패턴

RO 패턴은 Rust가 주도적으로 보안 데이터를 생성하고, 소멸의 책임도 지는 구조입니다. 암호화 키나 난수 등 최고 수준의 보안이 필요한 데이터를 생성할 때 사용됩니다.

* **메모리 할당**: Rust 내부에서 `SecureMemoryBlock`을 사용하여 페이지 크기 배수로 올림 처리된 메모리를 할당합니다.
* **보안 적용**: 할당된 메모리는 즉시 0으로 초기화되며, OS 레벨에서 메모리 페이징을 방지하기 위한 메모리 락(`mlock` 또는 `VirtualLock`, OS별 상이)이 수행됩니다.
* **Java로의 전달**: Rust는 내부의 `SecureBuffer`가 파기되지 않도록 소유권을 해제합니다. 이후 `ptr`, `len`, 그리고 `is_rust_owned = true` 플래그를 `FFIStandard` 구조체에 담아 Java로 반환합니다.
* **Java 측 사용**: Java의 `ExternFFIStandard` 객체가 이를 래핑하여 비즈니스 로직에서 안전하게 읽습니다.
* **파기 및 원자적 소거**: Java의 스코프가 종료되면, 컨텍스트가 플래그를 확인하고 Rust 측 해제 전용 함수인 `entlib_side_secure_free`를 호출합니다. Rust는 포인터를 다시 `Box::from_raw`를 통해 회수하여 명시적으로 `Drop`을 발생시킵니다. 이 과정에서 `Zeroizer::zeroize_raw`를 통한 하드웨어 수준의 강제 물리적 소거, OS 잠금 해제, 메모리 할당 해제가 안전하게 연쇄 호출됩니다.

### JO 패턴

JO 패턴은 Java가 데이터 공간을 선언하고, 물리적 소거 기능만 Rust의 강력한 제어력을 빌려 쓰는 Zero-Trust 기반 구조입니다. 외부 시스템에서 주입된 메모리의 안전한 파기를 보장합니다.

* **메모리 선언**: Java 측 `SensitiveDataContainer` 내부에서 FFM API의 `Arena`를 통해 메모리를 할당합니다.
* **보안 적용**: 할당된 메모리는 OS 레벨에서 메모리 페이징을 방지하기 위한 메모리 락이 수행됩니다.
* **Rust로의 전달**: 연산이 필요한 경우, Java는 `is_rust_owned = false`로 설정된 `FFIStandard` 구조체를 Rust로 보냅니다.
* **보안 검증**: Rust의 `SecureBuffer::from_raw_parts` 함수는 외부에서 주입된 메모리가 페이지 경계(`PAGE_SIZE` 배수)에 맞게 정렬되었는지 엄격하게 검증하여 부채널 공격 등 보안 취약점을 차단합니다.
* **소거 요청**: 연산 후 Java의 `try-with-resources` 스코프를 벗어나는 시점에, Java는 메모리를 즉시 해제하지 않고 Rust에 물리적 데이터 소거 로직 수행을 먼저 요청합니다(민감한 암호화 로직의 경우 소거는 Rust 측에서 미리 수행되고, Java에게 상태 코드를 전달할 수도 있습니다).
* **물리적 소거**: Rust 측에서 `SecureBuffer`가 `Drop`되며 전체 메모리 용량(`capacity`)에 대해 0으로 덮어씁니다. 이때 Rust는 메모리 소유권이 없으므로(`owned_block: None`), 메모리 해제는 수행하지 않고 외부 소유 메모리의 잠금만 해제합니다.
* **최종 해제 및 규정 준수**: Rust의 소거가 완료되었음을 확인한 후, Java 측 컨텍스트가 `Arena`를 닫아(`close()`) 최종적으로 메모리를 해제합니다. 이로써 데이터 생명 주기가 단일 병목점을 통과하여 FIPS 140 규격을 충족합니다.

### 핵심 구조체 역할 비교

`FFIStandard`와 `SecureBuffer`는 서로를 대체하는 것이 아니라, 통신 시점에 서로의 형태로 변환되는 관계입니다.

| 특성                   | RO 패턴                                                     | JO 패턴                                              |
|----------------------|-----------------------------------------------------------|----------------------------------------------------|
| **초기 메모리 할당**        | Rust (`SecureMemoryBlock::allocate_locked`)               | Java (`Arena`)                                     |
| **FFIStandard 플래그**  | `is_rust_owned = true`                                    | `is_rust_owned = false`                            |
| **SecureBuffer의 역할** | 데이터 생성 후 소유권을 우회하여 `FFIStandard`로 알맹이 추출                  | `FFIStandard`의 포인터를 래핑(`from_raw_parts`)하여 검증 후 소거 |
| **최종 메모리 해제**        | Rust (`entlib_side_secure_free` -> `deallocate_unlocked`) | Java (`Arena#close()`)                             |

## 인증 및 규정 준수 측면

FIPS 140에 따르면 어떤 데이터의 전체 생명 주기는 하나의 객체에서 관리되어야 합니다(단일 병목점을 통과해야 합니다). JO 패턴 측면에서 볼 때 데이터는 반드시 위의 객체로만 생성 가능합니다. 따라서 ELIB은 다음의 생명 주기가 완벽히 보장되어, FIPS 140을 준수합니다.

1. JO 패턴에서 컨텍스트 객체를 통해 데이터 선언
2. 연산 수행(필요한 경우 Rust 연산 수행)
3. 컨텍스트가 `try-with-resouces` 스코프를 벗어남 -> Rust 측에서 데이터 소거 로직 수행
4. 데이터 소거 완료 -> 지정된 `Arena`를 닫고 할당 해제