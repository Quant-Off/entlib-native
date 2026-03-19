# 보안 버퍼 크레이트 (entlib-native-secure-buffer)

> Q. T. Felix (수정: 26.03.19 UTC+9)
> 
> [English README](README_EN.md)

`entlib-native-secure-buffer`는 비밀 데이터의 전체 생명주기—할당, 사용, 소멸—에 걸쳐 물리적 메모리 보안을 보장하기 위해 설계된 크레이트입니다. 표준 `Vec<u8>`이나 힙(Heap) 할당 API는 할당자(Allocator)의 재사용 정책으로 인해 해제 후에도 이전 데이터가 힙 잔재(Heap Residue)로 남거나, OS의 페이지 스왑(Swap) 메커니즘을 통해 디스크에 기록될 수 있습니다. 본 크레이트는 이러한 메모리 포렌식(Memory Forensics) 공격 표면을 체계적으로 제거합니다.

## 보안 위협 모델

비밀 키 또는 암호학적 중간값(Intermediate Value)이 프로세스 힙에 잔존할 경우, 공격자는 프로세스 메모리 덤프, `/proc/self/mem` 접근, 동면(Hibernation) 이미지 또는 스왑 파티션 분석 등을 통해 해당 데이터를 복원할 수 있습니다. 본 크레이트는 세 가지 방어 계층을 통해 이 위협에 대응합니다. 첫째, 할당 시점에 제로화(Zeroization)하여 힙 잔재 유출을 차단합니다. 둘째, OS 레벨 메모리 잠금으로 페이지가 디스크에 기록되는 것을 방지합니다. 셋째, 소멸 시점에 컴파일러 최적화를 우회하는 물리적 메모리 소거를 수행합니다.

## 저수준 메모리 블록: `SecureMemoryBlock` 구조체

`SecureMemoryBlock`은 보안 요구사항을 충족하는 저수준 메모리 블록입니다. 표준 할당 API와 달리, 메모리 시작 주소가 반드시 시스템 페이지 경계에 정렬(Page-Aligned)되도록 `Layout`을 구성하여 할당합니다. `alloc_zeroed`를 통해 할당 즉시 내용 전체를 0으로 초기화하며, 이전 힙 데이터가 패딩 영역에 노출되는 것을 원천 차단합니다.

### 페이지 크기 획득

올바른 페이지 정렬과 캐시 라인 플러시를 수행하려면 런타임에 실제 시스템 페이지 크기를 파악해야 합니다. `std` 피처가 활성화된 Linux 환경에서는 libc나 `sysconf`를 거치지 않고 `/proc/self/auxv` 보조 벡터(Auxiliary Vector)를 원시 시스템 콜(`SYS_open`, `SYS_read`, `SYS_close`)로 직접 파싱하여 `AT_PAGESZ` 항목을 추출합니다. 이 방식은 중간 계층 라이브러리에 대한 의존을 제거하여 공급망 공격(Supply Chain Attack) 표면을 축소합니다. 비 Linux Unix 환경(macOS 등)에서는 POSIX `getpagesize()`를 호출합니다.

획득된 페이지 크기는 최솟값(4096) 및 2의 거듭제곱(Power-of-Two) 여부를 반드시 검증합니다. 검증에 실패하면 변조된 커널 응답으로 간주하고 패닉(Panic)을 발생시킵니다.

```rust
if size < 4096 || !size.is_power_of_two() {
    panic!("Security Violation: 안전하지 않거나 변조된 OS 페이지 크기가 감지되었습니다! ({})", size);
}
```

> [!IMPORTANT]
> `no_std` 환경에서는 런타임 조회가 불가능하므로 보수적 기본값 4096을 사용하며, 실제 배포 환경의 하드웨어 사양에 맞춘 포팅이 요구됩니다.

### OS 레벨 메모리 잠금

`allocate_locked`는 메모리 할당 후 OS 잠금을 시도합니다. Unix 계열에서는 `mlock(2)` 시스템 콜을 사용하며, Linux에서는 1차 잠금 실패 시 `RLIMIT_MEMLOCK` 리소스 한도를 `RLIM_INFINITY`로 동적 상향 조정한 뒤 2차 재시도합니다. Windows에서는 `VirtualLock` API를 통해 프로세스 워킹 셋(Working Set)에 해당 페이지를 고정합니다. 잠금에 최종 실패하면 이미 할당된 메모리를 즉시 해제하고 오류를 반환하여, 잠금되지 않은 상태로 비밀 데이터가 사용되는 상황을 방지합니다.

## 물리적 메모리 소거: `SecureZeroize` 트레이트

컴파일러는 소거 직후 메모리가 더 이상 읽히지 않는다고 판단하면 `memset`이나 단순 대입 루프를 데드 스토어 제거(Dead Store Elimination, DSE) 최적화로 삭제할 수 있습니다. `SecureZeroize` 트레이트와 `Zeroizer` 구현체는 아키텍처별 하드웨어 명령어를 직접 사용하여 DSE를 원천적으로 차단합니다.

### x86_64 소거 루틴

x86_64 환경에서는 인라인 어셈블리(`rep stosb`)를 사용하여 CPU 마이크로코드 수준에서 메모리를 0으로 채웁니다. 이 명령어는 컴파일러 IR 단계를 거치지 않으므로 DSE가 적용될 수 없습니다. 이후 L1/L2/L3 캐시에 잔존할 수 있는 데이터를 제거하기 위해 `clflush` 명령어를 캐시 라인 단위로 순차 실행합니다.

캐시 라인 크기는 하드코딩하지 않고 `CPUID Leaf 1`의 `EBX[15:8]` 필드(`CLFLUSH line size`)에서 동적으로 획득합니다($`\text{clflush\_size} = ((\texttt{ebx} \gg 8) \mathbin{\&} \texttt{0xFF}) \times 8`$). CPUID 조회 실패 또는 비정상 반환 시에는 64바이트를 안전한 기본값으로 사용합니다. 모든 플러시가 완료된 후 `mfence` 명령어로 메모리 버스 수준의 완전한 순서 보장(Full Memory Barrier)을 수행합니다.

```rust
// rep stosb: CPU 마이크로코드 수준 메모리 초기화 (DSE 불가)
asm!("rep stosb", inout("rcx") capacity => _, inout("rdi") ptr => _, in("al") 0u8, ...);
// clflush: 캐시에 잔존하는 데이터 강제 축출
asm!("clflush [{0}]", in(reg) flush_ptr, ...);
// mfence: 전체 메모리 배리어
asm!("mfence", ...);
```

### AArch64 소거 루틴

AArch64 환경에서는 `write_volatile`을 사용한 바이트 단위 초기화로 컴파일러 최적화를 억제합니다. 이후 캐시 정리를 위해 AArch64의 `dc civac`(Data Cache Clean and Invalidate by Virtual Address to Point of Coherency) 명령어를 실행합니다. 캐시 라인 크기는 `CTR_EL0` 시스템 레지스터의 `DminLine` 필드(`bits [19:16]`)에서 직접 획득합니다($`\text{cache\_line} = 4 \times 2^{\text{DminLine}}`$ 바이트). 모든 작업 완료 후 `dsb sy`로 완전한 데이터 동기화 배리어를 수행합니다.

### 폴백(Fallback) 소거 루틴

위 두 아키텍처 외의 환경에서는 OS가 제공하는 안전한 소거 API를 우선 사용합니다. `std` 피처가 활성화된 Unix 환경에서는 `explicit_bzero(3)` (OpenBSD, FreeBSD, Linux glibc 2.25+에서 지원)를, Windows에서는 `RtlSecureZeroMemory` Windows 커널 API를 호출합니다. 두 API 모두 컴파일러 DSE를 방지하도록 명세가 보장되어 있습니다. OS API가 전혀 부재한 `no_std` 베어메탈 환경에서는 `write_volatile` 기반 바이트 단위 루프를 폴백으로 사용하며, 이 경우 캐시 라인 플러시의 보장 여부는 대상 하드웨어에 종속됩니다.

모든 소거 경로는 종료 직전 `compiler_fence(SeqCst)` 및 `fence(SeqCst)`를 적용하여 컴파일러와 하드웨어 파이프라인 모두에서 소거 연산이 선행 완료됨을 보장합니다.


## 고수준 보안 버퍼: `SecureBuffer` 구조체

`SecureBuffer`는 `SecureMemoryBlock`을 래핑하여 데이터의 전체 생명주기를 안전하게 관리하는 고수준 API입니다. Rust 내부에서 할당한 소유(Owned) 메모리와, Java FFM API 등 외부 시스템에서 전달된 비소유(Borrowed) 메모리를 `owned_block: Option<SecureMemoryBlock>` 필드로 구분하여 처리합니다.

### 소유 메모리 생성: `new_owned`

`new_owned(size)`는 `SecureMemoryBlock::allocate_locked`에 위임하여 페이지 정렬된, 0으로 초기화된, OS 잠금이 적용된 메모리를 할당합니다. `owned_block`에 할당 정보가 기록되며, `Drop` 시점에 소거 후 해제 책임이 `SecureMemoryBlock`으로 위임됩니다.

### 외부 메모리 래핑: `from_raw_parts`

`from_raw_parts(ptr, len)`은 Zero-Trust 원칙에 따라 외부에서 주입된 포인터가 페이지 경계에 정렬되어 있는지 엄격히 검증합니다. 포인터 주소(`ptr as usize`)와 길이(`len`) 모두 시스템 페이지 크기의 배수여야 하며, 하나라도 위반하면 즉시 오류를 반환합니다. 검증 통과 후에는 외부 메모리에 대해서도 OS 잠금을 시도합니다. `owned_block`은 `None`으로 설정되어 `Drop` 시점에 메모리 해제가 수행되지 않으며, 실제 해제는 원래 소유자(예: Java Arena)에 위임됩니다.

```rust
if !(ptr as usize).is_multiple_of(ps) {
    return Err("Security Violation: External memory pointer is not page-aligned.");
}
```

### 자동 소거와 해제: `Drop` 구현

`SecureBuffer`의 `Drop` 구현은 소유권 여부와 무관하게 항상 `Zeroizer::zeroize_raw`를 통해 `capacity` 전체를 소거합니다. 소거 대상 범위가 유효 데이터 길이(`len`)가 아닌 할당 전체 용량(`capacity`)임에 주목해야 합니다. 이는 페이지 정렬에 의해 생성된 패딩 영역에도 이전 데이터가 잔존할 수 있기 때문입니다. 소거 완료 후, 소유 메모리는 `SecureMemoryBlock::deallocate_unlocked`를 통해 잠금 해제 및 `dealloc`을 수행하고, 비소유 메모리는 잠금 해제만 수행합니다.

## 피처 플래그

`std` 피처는 페이지 크기 런타임 조회, OS 메모리 잠금(`mlock`/`VirtualLock`), `explicit_bzero`/`RtlSecureZeroMemory` 폴백 소거 루틴을 활성화합니다. 이 피처를 비활성화하면 크레이트는 `no_std` 환경에서 동작하며, 페이지 크기는 4096으로 고정되고 메모리 잠금 및 OS API 폴백은 비활성화됩니다. 아키텍처별 인라인 어셈블리 소거 루틴(x86_64, AArch64)은 피처와 무관하게 항상 활성화됩니다.