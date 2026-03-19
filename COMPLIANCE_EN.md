# Certification and Compliance

> [!IMPORTANT]
> Passing the test vectors does not mean that each cryptographic module and algorithm implementation is fully validated.
> These CAVP (Cryptographic Algorithm Validation Program) test vector validations have no legal effect and merely indicate that the cryptographic algorithm 'operates normally.'

NIST CAVP is a validation process for individual algorithms. For use in actual production environments, CMVP (Cryptographic Module Validation Program) validation according to FIPS 140-2/3 is required. In other words, CAVP certification is a mandatory prerequisite for CMVP certification.

## RNG SP 800-90A Rev. 1 (B, C)

> [NIST CAVP - Random Number Generators](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Random-Number-Generators)

- [ ] Hash DRBG
- [ ] HMAC DRBG
- [ ] CTR DRBG

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do)

- [ ] Hash DRBG
- [ ] HMAC DRBG
- [ ] CTR DRBG

## SHA2 (FIPS 180-4)

> [NIST CAVP - Secure Hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)

- [ ] SHA-224
- [ ] SHA-256
- [ ] SHA-384
- [ ] SHA-512

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do)

- [X] SHA-224
- [X] SHA-256
- [X] SHA-384
- [X] SHA-512

## SHA3 (FIPS 202)

> [NIST CAVP - Secure Hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)

- [X] SHA-3 224
- [X] SHA-3 256
- [X] SHA-3 384
- [X] SHA-3 512
- [X] XOF (SHAKE128)
- [X] XOF (SHAKE256)

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do)

- [X] SHA-3 224
- [X] SHA-3 256
- [X] SHA-3 384
- [X] SHA-3 512

## HKDF (SP 800-108)

> [NIST CAVP - Key Derivation](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation)

- [ ] HKDF SHA-2
- [ ] HKDF SHA-3

## HMAC (FIPS 198-1)

> [NIST CAVP - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Message-Authentication)

- [ ] HMAC

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do)

- [X] HMAC (SHA-2)
- [X] HMAC (SHA-3)

## Digital Signature (Composite)

> [Post-Quantum-Cryptography/KAT/MLDSA](https://github.com/post-quantum-cryptography/KAT/tree/main/MLDSA) (FIPS 204)

- [ ] ML-DSA-44 KeyPair generation
- [ ] ML-DSA-44 Sign/Verify
- [ ] ML-DSA-65 KeyPair generation
- [ ] ML-DSA-65 Sign/Verify
- [ ] ML-DSA-87 KeyPair generation
- [ ] ML-DSA-87 Sign/Verify
