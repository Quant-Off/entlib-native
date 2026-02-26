# EntanglementLib Native

> [Korean INTRODUCTION](INTRODUCTION.md)

> [!WARNING]
> The content of this document may differ significantly from the current functionality of `entlib-native`!

The core logic of the [EntanglementLib](https://github.com/Quant-Off/entanglementlib) is all processed within this [Rust-based native library](https://github.com/Quant-Off/entlib-native). In this document, we will simply refer to it as "Native".

In this document, I would like to technically pinpoint exactly how this Native works with the EntanglementLib and how it performs security operations, but since this content is extremely vast, I will organize it in detail separately on [our documentation site](https://docs.qu4nt.space/en/docs/projects/entanglementlib/entlib-native).

# Design Philosophy

The design philosophy of Native can be summarized in one sentence: **All code involved in security operations must be controllable by itself, without external dependencies.**

This principle is not simply an obsession with excluding external crates. It means that the developer must be able to directly design the entire lifecycle of security operations and explicitly guarantee when each byte is created and when it is erased. I cannot control what optimizations external libraries perform internally or what temporary buffers they leave behind. Therefore, all security operations performed in Native are implemented directly.

Based on this philosophy, Native adheres to the following four principles.

**1. Guarantee of Memory Erasure.** All structures handling sensitive data have their internal states completely erased the moment they go out of scope. By combining Rust's `Drop` trait and `write_volatile`, we force the compiler's Dead Code Elimination (DCE) optimization not to skip the erasure logic, and guarantee the erasure order with `compiler_fence`.

**2. Constant Time Operations.** All operations dependent on secret data, such as comparison, selection, and branching, are completed within the same time regardless of the input value. Instead of conditional branching, we use bitmask-based selection, and on `x86_64` and `aarch64` architectures, we guarantee this at the instruction level through inline assembly without compiler intervention.

**3. Hardware-Level Control.** Random number generation directly calls the CPU's hardware entropy sources (`rdseed`, `rdrand`, `rndr`), and constant time operations also directly write assembly instructions for each architecture. It is based on guarantees provided by hardware, not abstraction at the software layer.

**4. Auditable Code.** Code involved in security operations is completed within this repository without external crates. The scope of code to trace during security reviews is clear, and the attack surface of the supply chain due to dependency chains is fundamentally blocked.

# Interaction

Native is called safely and quickly from the EntanglementLib side via the [FFM API (Linker API)](https://openjdk.org/jeps/454).

When processing sensitive data in the EntanglementLib, the [Sensitive Data Container](https://docs.qu4nt.space/en/docs/projects/entanglementlib/sensitive-data-container) logic transmits the memory address to Native via `MemorySegment`, and Native receives the memory address, performs security operations, completely erases it, and transmits the Raw result to the EntanglementLib. In other words, since there is absolutely no need to store data in Heap memory overall, the Garbage Collector (GC) of the EntanglementLib does not need to make foolish mistakes.

# Security of All Operations

Native is basically implemented without dependence on external crates for all security operations according to its security philosophy. However, naturally, this is not directly connected to security. Then how does Native perform operations safely?

## Volatile Memory Erasure

The most basic and most important thing in security operations is "that used sensitive data does not remain in memory". General zeroing code (for example, a loop filling an array with 0) can be judged by the compiler as "writes that are not read later" and removed during the optimization process. This is so-called dead code elimination.

In Native, we use `core::ptr::write_volatile` to force all erasure operations to penetrate compiler optimizations. Subsequently, we set a memory barrier with `compiler_fence(Ordering::SeqCst)` to guarantee that erasure is completed in the intended order. This pattern is consistently applied to hash internal states (`KeccakState`, `Sha256State`, etc.), security buffers (`SecureBuffer`), random number generator states (`MixedRng`), and even temporary variables used during operations.

## Constant Time Operations

Timing side-channel attacks infer secret data by observing minute differences in operation time. Native's `constant_time` module is designed so that all operations dependent on secret data execute the same instruction path regardless of the input value.

The core principle is not to use conditional branching (`if-else`) but to select results only with bitwise operations. Comparison results are returned as bitmasks (`0` or `!0`) rather than `bool`, and values are selected without branching through this mask. We have implementations of three tiers for each architecture:

- **Tier 1 (Full Assembly):** Implemented in pure inline assembly for 32-bit and 64-bit types on `x86_64`, `aarch64`. It fundamentally blocks the possibility of the Rust compiler rearranging instructions or converting them to branches.
- **Tier 2 (Assembly Barrier):** Combines assembly optimization barriers and Rust bitwise operations for 8-bit, 16-bit, and 128-bit types on the same architectures.
- **Tier 3 (Fallback):** Uses `core::hint::black_box` on other architectures to suppress optimizations and implements with pure Rust bitwise operations.

These constant time primitive operations are directly used in actual operations such as `Base64` encoding/decoding.

## Hardware Entropy

It is difficult to guarantee the quality of entropy sources with only software Pseudo-Random Number Generators (PRNG). Native's random number generator directly calls hardware entropy sources provided by the CPU. In `x86_64` environments, it prioritizes using `rdseed` instructions compliant with [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final), and in `aarch64` environments, it reads the `RNDR` register of ARMv8.5-A.

If additional non-linear mixing is required for pure hardware output, a stream using hardware entropy as key and nonce is generated through `MixedRng` based on the ChaCha20 core block. Internal states and intermediate values on the stack used in this process are also volatilely erased after operation completion.

## SecureBuffer

Native's operation results are not directly delivered to the Java Heap as general `Vec<u8>` or byte arrays. Instead, they are contained in the `SecureBuffer` structure and maintained in Off-Heap memory, and only the raw pointer of that memory is delivered to the Java side.

The reason this design is necessary is clear. Java's Garbage Collector freely copies and moves Heap objects, and does not guarantee when the data at the original location will be erased. `SecureBuffer` fundamentally avoids this problem. When Java finishes using the data and requests release, the internal bytes are volatilely erased by the `Drop` trait, and then the memory is returned.

# Composition

Native is composed of a virtual manifest-based workspace, and each crate is granularized to have clear responsibility boundaries. Under `crypto/`, crates for performing `Base64`, `Hash`, or algorithm operations are located, and under `internal/`, crates for `ffi` integration and quantum-related utilities are included.