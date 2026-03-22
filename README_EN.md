# Entanglement Library Native

[![Version](https://img.shields.io/badge/version-1.1.0%20Alpha-blue?style=for-the-badge)](https://github.com/Quant-Off/entlib-native)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entlib-native)

![lol](entanglementlib-logo.png)

A Rust-based native library responsible for all the security features of the [EntanglementLib](https://github.com/Quant-Off/entanglementlib).

> [Korean README](README.md)

Rust is the most suitable native base language for fully implementing the security features of EntanglementLib. The biggest advantage of this language is that it guarantees memory stability without performance degradation. In detail, the [Ownership concept](https://doc.rust-kr.org/ch04-00-understanding-ownership.html) facilitates resource management, and the **concurrency feature without data competition** enhances security even in a multi-threaded environment.

It is flexible in itself, such as easy module management and encapsulation consistent with Python or JPMS (Java Platform Module System), and the easy connection with Java through FFI (Foreign Function Interface) is sufficiently attractive.

---

**Currently**, this native library provides the following features(indicating that these items have been stabilized):

- `core`
    - Secure Buffer that guarantees memory erasure
    - Constant-Time operation
    - RNG(HashDRBG)
    - Base65, Hex en/decoding
- `crypto`
    - HASH (including SHA-2, 3, SHAKE)
    - HKDF (for all hash algorithms)
    - HMAC (for all hash algorithms)

Each feature is managed as a separate crate under a specific directory, and the root is configured as a virtual manifest, making it easy to manage the sub-crates. The `entlib-native-ffi` crate that implements FFI is used to deliver the main functions to be used on the Java side. These features (and miscellaneous items) are managed under the `internal` directory.

## Security Level

The Entanglement Library aims for Common Criteria (CC) Evaluation Assurance Level (EAL) 4. Currently, all implementations are based on the National Institute of Standards and Technology (NIST) Federal Information Processing Standards (FIPS) 140-3, and CAVP verification is conducted internally whenever an individual algorithm implementation is created or changed.

Of course, this is not a formal verification, but only an internal evaluation. The test vectors provided to CAVP are simply a guide to 'this algorithm works normally'. For Cryptographic Module Validation Program (CMVP), all implemented cryptographic algorithms must operate normally and clearly follow the FIPS standard without any error.

The final security goal of the Entanglement Library is to obtain a grade of CC EAL5+ or higher (EAL7). This requires difficult and complex preparations such as strict design at the hardware level and formal specifications, but it is planned to reach military-grade security in the future. I am in the process of designing the architecture for this.

## Future Plans

We need to implement a variety of supported classic cryptographic algorithm modules.

- AEAD
  - [ ] ChaCha20
- Block Cipher
  - [ ] AES (128, 192, 256)
  - [ ] ARIA (128, 192, 256)
- KDF (Key Derivation Function)
  - [ ] PBKDF2
  - [ ] Argon2id
- Digital Signature
  - [ ] RSA (2048, 4096, 8192)
  - [ ] ED25519, ED448 Signatures
  - [ ] X25519, X448 Key Agreement
- De/Serializer, En/Decoder
  - [ ] ASN.1 Encoder/Decoder
  - [ ] PEM/DER Serializer
- PKC Standard Pipeline
  - [ ] PKCS #8
  - [PKCS #11](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
    - [ ] C-API FFI Mapping
    - [ ] Dynamic Loader (System Call-based)

Post-Quantum Cryptography (PQC) algorithms aim to achieve the following goals.

- [ ] FIPS 203 (Module Lattice-based Key Encapsulation Mechanism, ML-KEM)
- [x] FIPS 204 (Module Lattice-based Digital Signature Algorithm, ML-DSA)
- [ ] FIPS 205 (Stateless Hash-based Digital Signature Algorithm, SLH-DSA)

Additionally, the following TLS features must be supported.

- [ ] TLS 1.3
- [ ] X25519MLKEM768 in accordance with `draft-ietf-tls-ecdhe-mlkem`
- [ ] X9.146 QTLS Extension Standard

## Certification and Compliance Required

In order to fully comply with the aforementioned certification and compliance matters, the cryptographic algorithm is continuously verified, and the FIPS standard of the Entanglement Library itself is also checked. I will record the specific progress on CAVP in another document.

Therefore, if you use `entlib-naitve`, please provide or use it as an 'experimental' feature.

> [!NOTE]
> Features that have passed strict certification and regulatory review will be updated immediately. I will make sure that this information is available in [this document](COMPLIANCE_EN.md).

# Contribution

My favorite security group, `Legion of the BouncyCastle Inc`, has started developing [`bc-rust`](https://github.com/bcgit/bc-rust/), and I have gained a lot of useful technical inspiration from it, such as cryptographic algorithms and key management methods. They have always been my strength since I started developing the Entanglement Library. Anyway, I will maintain this development speed (10 hours a day, 7 days a week, but commits are slow), and I will continue to revise this document according to future updates. In the end, I plan to develop towards this goal.

> [!TIP]
> Your feedback is always a great help. If you want to contribute to this project, please refer to the issues or the [contribution document](CONTRIBUTION_EN.md)!