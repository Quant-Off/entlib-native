# EntanglementLib: Native Bridge

> [English README](README_EN.md)

> [What does this library do?](INTRODUCTION.md) Detailed technical explanations can be found in the [Quant Team Public Documentation](https://docs.qu4nt.space/docs/projects/entanglementlib/entlib-native).

The core functionality of the [EntanglementLib](https://github.com/Quant-Off/entanglementlib/blob/master/README_EN.md) resides in the Rust-based native library. All security operations are performed entirely within this native component.

Rust is the most suitable native base language for perfectly executing EntanglementLib’s security features. Its greatest strength is guaranteeing memory safety without any performance penalty. In detail, the [Ownership concept](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) makes resource management straightforward, and **data-race-free concurrency** strengthens security even in multi-threaded environments. It offers consistent module management aligned with Python or JPMS (Java Platform Module System), easy encapsulation, and other flexible language characteristics. The ability to connect seamlessly with Java via FFI (Foreign Function Interface) is particularly compelling.

All security operations of EntanglementLib are executed in this native layer. Specifically, it provides the following capabilities:

- [X] Hardware true random, mixed random, and quantum random number (Quantum RNG) generation
- [X] AEAD encryption (ChaCha20)
- [X] Secure Buffer that guarantees memory erasure
- [X] Constant-Time operations
- [X] Hash functions (including SHA2, SHA3, SHAKE)

Each feature is managed as a separate crate. The root uses a virtual manifest, making sub-crate management straightforward. In addition, a dedicated crate implements the FFI functions to fundamentally block incorrect calls when the native is used from the Java side. This crate serves to expose only the essential functions that the Java side should call.

This native library uses **no external dependencies (crates)** for the implementation of its core security features. In other words, it fundamentally does not trust any resources imported from outside. This development philosophy fully supports the **Zero Trust principle**, and the resulting single artifact (the EntanglementLib) operates smoothly even in closed environments. This perfectly aligns with the **Air-Gapped Ready** principle.

Ultimately, this native is a precious resource cultivated in a strict environment and is actively and safely utilized throughout the EntanglementLib.

## Future Plans

This native still has a long way to go. We must implement a wide variety of classical encryption algorithm modules.

- [ ] AES (128, 192, 256)
- [ ] ARIA (128, 192, 256)
- [ ] RSA (2048, 4096, 8192)
- [ ] ED25519, ED448 signatures
- [ ] X25519, X448 key agreement

In addition, essential cryptographic primitives such as HMAC and HKDF must be provided.

The Post-Quantum Cryptography (PQC) algorithms have the following targets:

- [ ] [FIPS 203 (Module Lattice-based Key Encapsulation Mechanism, ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [ ] [FIPS 204 (Module Lattice-based Digital Signature Algorithm, ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [ ] [FIPS 205 (Stateless Hash-based Digital Signature Algorithm, SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)

Once the above PQC algorithms are implemented, the following TLS features must also be provided:

- [ ] TLS 1.3
- [ ] X25519MLKEM768 according to [`draft-ietf-tls-ecdhe-mlkem`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)

PKIX, JWT and CWT, OTP, and many others — there is clearly still a long road ahead.

## Certification and Compliance Requirements

Implementation alone is not enough. Every feature implemented in this native must completely follow the security implementation (specification) requirements set by international certification authorities and must obtain formal certification. Until then, no algorithm is considered “safe.” Hidden variables can surface at any time.

Therefore, when using any functionality from this native, please treat it as an **experimental** feature or use it with that understanding.

> [!NOTE]
> Features that have passed strict certification and regulatory review will be updated immediately. You can check the relevant information in [this document](COMPLIANCE_EN.md).

# Inspiration and Contribution

Coincidentally, the respected security collective `Legion of the BouncyCastle Inc` has begun development of [`bc-rust`](https://github.com/bcgit/bc-rust/), providing a great deal of inspiration that is highly relevant to EntanglementLib’s bridging technology. They have been a constant source of strength for me from the very beginning of EntanglementLib development up to now. In any case, I will maintain this development pace and will continue to update this document in line with future releases. Ultimately, development will proceed steadily toward this goal.

> [!TIP]
> Your feedback is always an enormous help. If you would like to contribute to this project, please refer to [this guide](CONTRIBUTION_EN.md)!

# Benchmarking

Benchmarking of this native library is performed using the `criterion` crate. Detailed results for each benchmark can be found in the [benchmarks subdirectory](benchmarks).