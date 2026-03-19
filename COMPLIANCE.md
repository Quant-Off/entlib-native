# 인증 및 규정 준수 사항

> [!IMPORTANT]
> 테스트 벡터를 통과했다고 해서 각 암호화 모듈 및 알고리즘 구현이 완전히 검증됐다는 것이 아닙니다.
> 이러한 CAVP(Cryptographic Algorithm Validation Program) 테스트 벡터 검증은 아무런 효력이 없으며, 암호 알고리즘이 '정상적으로 작동한다'를 알려줄 뿐 입니다.

NIST CAVP는 단일 알고리즘에 대한 검증 작업입니다. 실제 프로덕션 환경에서 사용되기 위해서는 FIPS 140-2/3에 따른 CMVP(Cryptographic Module Validation Program) 검증이 필요합니다. 즉, CAVP 인증은 CMVP 인증의 필수 선수 조건입니다.

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
