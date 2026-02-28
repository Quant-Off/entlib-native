# 인증 및 규정 준수 사항

> [!IMPORTANT]
> 테스트 벡터를 통과했다고 해서, 각 암호화 모듈 및 알고리즘 구현이 완전히 검증됐다는 것이 아닙니다.
> 이러한 테스트 벡터의 사용은 CAVP(Cryptographic Algorithm Validation Program)를 통해 얻은 검증을 대체하지 않습니다.

NIST CAVP는 단일 알고리즘에 대한 검증 작업입니다. 실제 프로덕션 환경에서 사용되기 위해서는 FIPS 140-2/3에 따른 CMVP(Cryptographic Module Validation Program) 검증이 필요합니다. 즉, CAVP 인증은 CMVP 인증의 필수 선수 조건입니다.

## RNG

> [NIST CAVP - Random Number Generators](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Random-Number-Generators)

- [ ] SP 800-90A DRBG(Deterministic Random Bit Generators)

## SHA2

> [NIST CAVP - Secure Hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) (ISO/IEC 10118-3)

- [ ] FIPS 180-4 SHA Test Vectors for Hashing Bit/Byte-Oriented Messages

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do) KS X ISO/IEC 10118-3:2001

- [ ] Security techniques - Hash-functions - Part 3: Dedicated hash-functions (2018)

## SHA3

> [NIST CAVP - Secure Hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) (ISO/IEC 10118-3)

- [X] FIPS 202 SHA-3 Hash Function Test Vectors for Hashing Bit/Byte-Oriented Messages
- [X] FIPS 202 SHA-3 XOF Test Vectors for Bit/Byte-Oriented Output

> [KCMVP](https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do) KS X ISO/IEC 10118-3:2001

- [X] Security techniques - Hash-functions - Part 3: Dedicated hash-functions (2018)