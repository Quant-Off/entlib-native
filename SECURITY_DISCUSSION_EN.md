# Security Discussion

> [Korean SECURITY DISCUSSION](SECURITY_DISCUSSION.md)

`entlib-native` clearly provides secure operations for data management and constant-time, but before we can call it 'secure', we need to discuss the problem of aggressive optimization in the LLVM compiler.

## The Chronic Problem of the LLVM Compiler

Technically, LLVM, the backend of Rust, performs optimizations with the top priority of improving the average execution speed of the code. In this process, there are continuous reports of cases where constant-time bit operations or mathematical tricks intentionally written by developers to defend against side-channel attacks (Timing Side-Channel Attacks) are arbitrarily converted into conditional branches (e.g., `cmp` followed by `jmp` in assembly) by LLVM's `SimplifyCFG` pass, etc.

Frameworks, libraries, etc. that provide cryptographic functions based on high-security principles like `entlib-native` must implement all core security modules by encapsulating them directly without external dependencies. In an environment that must pass strict verification at the level of FIPS 140-2/3 and CC EAL2 (or EAL3), strict measures must be taken to prevent this.

To get straight to the point, the solution we came up with is to use inline assembly. This is the most reliable way to create a black-box section where the LLVM optimizer can never intervene. In parts where conditional logic is needed, instead of software-based bit operations, we should directly call the constant-time conditional move instructions supported by the hardware. For example, the `x86_64` architecture can use the conditional move (`cmov`) instruction, and the `aarch64` architecture can use the conditional select (`csel`) instruction. This approach bypasses the compiler's instruction selection stage, so it can completely prevent the insertion of branch statements even if the compiler version is updated.

We can discuss compiler barriers and volatile operations and memory barriers further. A compiler barrier (`core::hint::black_box`) instructs the compiler to ignore a specific value during the optimization analysis process. This can prevent the compiler from performing constant folding by predicting the input value or performing Dead Code Elimination (DCE).

However, as the official Rust documentation also states, `black_box` only suppresses optimization and does not absolutely guarantee cryptographic constant-time execution. In other words, while it can prevent the value of a variable from being optimized, it cannot completely control the compiler from compiling the operation that processes that variable into a branch statement. Therefore, it should only be approached as a supplementary measure, not the main defense.

What about volatile operations and memory barriers? According to this approach, `core::ptr::read_volatile` and `write_volatile` can be used to prevent optimization throughout the entire lifecycle of data (from allocation to erasure). When implementing memory erasure that is impossible to forensics, if you use normal memory writes, LLVM will judge it as "a memory write that is not used afterwards" and delete the erasure logic itself (Dead Store Elimination, DSE). Volatile operations prevent the compiler from omitting or reordering memory accesses.

All operations in `entlib-native` clearly support constant-time operations. As a result, it also shows the technical moment of controlling LLVM-side optimization by using limited use of inline assembly and compiler barriers, volatile operations, and memory barriers.

## Regarding Unsafe Operations

However, we can continue the discussion in the context that `entlib-native` basically "uses unsafe operations" to solve the problem of aggressive LLVM optimization. This is because to achieve cryptographic stability, we must escape the control of the compiler, but this leads to the dilemma of having to release Rust's core value of "memory stability" ourselves.

`entlib-native` must pass strict security certification, and the use of `unsafe` in this project is an explicit declaration that it proves and takes responsibility for security and mathematical/logical integrity on behalf of the compiler.

"Safe" in Rust is to enforce the rules of Ownership, Borrowing, and Lifetime at compile time, and it means 'no Undefined Behavior', but it is defenseless against timing attacks or residual memory theft. In other words, the memory safety rules rather cause security vulnerabilities such as side channels and DSE, so it is thought that we must intentionally acquire hardware-dependent control (unsafe) to defend against them. We will define this as the separation of the cryptographic domain and the memory domain.

We support the principles of safe abstraction and complete encapsulation. That is, `unsafe` code should never be spread globally, but should be completely encapsulated behind a publicly available API signature. Code that performs inline assembly or `volatile` operations should be isolated into the smallest unit of function, and before entering an `unsafe` block, boundary checks and `null` pointer checks for data brought in from the outside must be completed in the Safe area.