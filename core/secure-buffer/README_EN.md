# Secure Buffer Crate (entlib-native-secure-buffer)

> Q. T. Felix (Modified: 26.03.19 UTC+9)
> 
> [Korean README](README.md)

`entlib-native-secure-buffer` is a crate designed to ensure physical memory security throughout the entire lifecycle of secret data—allocation, use, and destruction. Standard `Vec<u8>` or heap allocation APIs can leave previous data as heap residue after deallocation due to the allocator's reuse policy, or it can be written to disk through the OS's page swap mechanism. This crate systematically eliminates these memory forensics attack surfaces.

## Security Threat Model

If a secret key or cryptographic intermediate value remains in the process heap, an attacker can recover the data through a process memory dump, `/proc/self/mem` access, hibernation image analysis, or swap partition analysis. This crate counters this threat with three layers of defense. First, it prevents heap residue leakage by zeroizing at the time of allocation. Second, it prevents pages from being written to disk with OS-level memory locking. Third, it performs physical memory erasure that bypasses compiler optimizations at the time of destruction.

## Low-Level Memory Block: `SecureMemoryBlock` Struct

`SecureMemoryBlock` is a low-level memory block that meets security requirements. Unlike standard allocation APIs, it allocates by configuring the `Layout` so that the memory start address is always page-aligned. It immediately initializes the entire content to 0 upon allocation via `alloc_zeroed`, fundamentally blocking the exposure of previous heap data in the padding area.

### Obtaining Page Size

To perform correct page alignment and cache line flushing, the actual system page size must be determined at runtime. In a Linux environment with the `std` feature enabled, it directly parses the `/proc/self/auxv` auxiliary vector using raw system calls (`SYS_open`, `SYS_read`, `SYS_close`) to extract the `AT_PAGESZ` entry, without going through libc or `sysconf`. This approach reduces the supply chain attack surface by eliminating dependencies on intermediate libraries. In non-Linux Unix environments (macOS, etc.), it calls the POSIX `getpagesize()`.

The obtained page size is always verified for a minimum value (4096) and whether it is a power-of-two. If the verification fails, it is considered a tampered kernel response and a panic is triggered.

```rust
if size < 4096 || !size.is_power_of_two() {
    panic!("Security Violation: Unsafe or tampered OS page size detected! ({})", size);
}
```

> [!IMPORTANT]
> In a `no_std` environment, runtime lookup is not possible, so a conservative default of 4096 is used, and porting is required to match the hardware specifications of the actual deployment environment.

### OS-Level Memory Locking

`allocate_locked` attempts to lock the memory after allocation. On Unix-like systems, it uses the `mlock(2)` system call, and on Linux, if the primary lock fails, it dynamically raises the `RLIMIT_MEMLOCK` resource limit to `RLIM_INFINITY` and retries a second time. On Windows, it pins the page to the process's working set via the `VirtualLock` API. If the lock ultimately fails, it immediately deallocates the already allocated memory and returns an error, preventing the use of secret data in an unlocked state.

## Physical Memory Erasure: `SecureZeroize` Trait

If the compiler determines that the memory is no longer read after erasure, it can delete the `memset` or simple assignment loop as a Dead Store Elimination (DSE) optimization. The `SecureZeroize` trait and `Zeroizer` implementation fundamentally block DSE by directly using architecture-specific hardware instructions.

### x86_64 Erasure Routine

In an x86_64 environment, it uses inline assembly (`rep stosb`) to fill the memory with zeros at the CPU microcode level. Since this instruction does not go through the compiler IR stage, DSE cannot be applied. After that, to remove any data that may remain in the L1/L2/L3 caches, the `clflush` instruction is executed sequentially on a cache line basis.

The cache line size is not hardcoded but is dynamically obtained from the `EBX[15:8]` field (`CLFLUSH line size`) of `CPUID Leaf 1` ($\text{clflush\_size} = ((\texttt{ebx} \gg 8) \mathbin{\&} \texttt{0xFF}) \times 8$). If the CPUID lookup fails or returns an abnormal value, 64 bytes are used as a safe default. After all flushes are complete, a full memory barrier is performed at the memory bus level with the `mfence` instruction.

```rust
// rep stosb: CPU microcode level memory initialization (DSE not possible)
asm!("rep stosb", inout("rcx") capacity => _, inout("rdi") ptr => _, in("al") 0u8, ...);
// clflush: Force eviction of data remaining in the cache
asm!("clflush [{0}]", in(reg) flush_ptr, ...);
// mfence: Full memory barrier
asm!("mfence", ...);
```

### AArch64 Erasure Routine

In an AArch64 environment, compiler optimizations are suppressed by byte-wise initialization using `write_volatile`. After that, for cache cleaning, the AArch64 `dc civac` (Data Cache Clean and Invalidate by Virtual Address to Point of Coherency) instruction is executed. The cache line size is obtained directly from the `DminLine` field (`bits [19:16]`) of the `CTR_EL0` system register ($\text{cache\_line} = 4 \times 2^{\text{DminLine}}$ bytes). After all operations are complete, a full data synchronization barrier is performed with `dsb sy`.

### Fallback Erasure Routine

In environments other than the two architectures above, the secure erasure API provided by the OS is used first. In a Unix environment with the `std` feature enabled, `explicit_bzero(3)` (supported on OpenBSD, FreeBSD, Linux glibc 2.25+) is used, and on Windows, the `RtlSecureZeroMemory` Windows kernel API is called. Both APIs are specified to prevent compiler DSE. In a `no_std` bare-metal environment where there is no OS API at all, a `write_volatile`-based byte-wise loop is used as a fallback, in which case the guarantee of cache line flushing depends on the target hardware.

All erasure paths apply `compiler_fence(SeqCst)` and `fence(SeqCst)` just before termination to ensure that the erasure operation is completed first in both the compiler and the hardware pipeline.


## High-Level Secure Buffer: `SecureBuffer` Struct

`SecureBuffer` is a high-level API that wraps `SecureMemoryBlock` to securely manage the entire lifecycle of data. It handles owned memory allocated within Rust and borrowed memory passed from external systems such as the Java FFM API by distinguishing them with the `owned_block: Option<SecureMemoryBlock>` field.

### Creating Owned Memory: `new_owned`

`new_owned(size)` delegates to `SecureMemoryBlock::allocate_locked` to allocate page-aligned, zero-initialized, and OS-locked memory. The allocation information is recorded in `owned_block`, and the responsibility for erasure and deallocation at the time of `Drop` is delegated to `SecureMemoryBlock`.

### Wrapping External Memory: `from_raw_parts`

`from_raw_parts(ptr, len)` strictly verifies that the pointer injected from the outside is page-aligned according to the Zero-Trust principle. Both the pointer address (`ptr as usize`) and the length (`len`) must be multiples of the system page size, and if either is violated, an error is returned immediately. After passing verification, it also attempts to lock the external memory with the OS. `owned_block` is set to `None` so that memory deallocation is not performed at the time of `Drop`, and the actual deallocation is delegated to the original owner (e.g., Java Arena).

```rust
if !(ptr as usize).is_multiple_of(ps) {
    return Err("Security Violation: External memory pointer is not page-aligned.");
}
```

### Automatic Erasure and Deallocation: `Drop` Implementation

The `Drop` implementation of `SecureBuffer` always erases the entire `capacity` through `Zeroizer::zeroize_raw`, regardless of ownership. It is important to note that the scope of erasure is the entire allocated capacity (`capacity`), not the valid data length (`len`). This is because previous data may remain in the padding area created by page alignment. After erasure is complete, owned memory is unlocked and `dealloc` is performed through `SecureMemoryBlock::deallocate_unlocked`, while borrowed memory is only unlocked.

## Feature Flags

The `std` feature enables page size runtime lookup, OS memory locking (`mlock`/`VirtualLock`), and the `explicit_bzero`/`RtlSecureZeroMemory` fallback erasure routine. Disabling this feature makes the crate operate in a `no_std` environment, where the page size is fixed at 4096 and memory locking and OS API fallbacks are disabled. Architecture-specific inline assembly erasure routines (x86_64, AArch64) are always enabled regardless of the feature.