# 얽힘 라이브러리: 네이티브 브릿지

> [English README](README_EN.md)

> [이 라이브러리는 무슨 기능을 할까요?](INTRODUCTION.md) 기술에 대한 세부적 설명은 [퀀트 팀 공개 문서](https://docs.qu4nt.space/docs/projects/entanglementlib/entlib-native) 에서 확인할 수 있습니다.

[얽힘 라이브러리(EntanglementLib)](https://github.com/Quant-Off/entanglementlib)의 핵심적 기능은 Rust 기반의 네이티브 라이브러리에 있습니다. 모든 보안 연산을 이 네이티브에서 수행하는 겁니다.

EntanglementLib의 보안 기능을 완벽히 수행하기 위한 네이티브 베이스 언어는 Rust가 가장 잘 어울립니다. 이 언어의 가장 큰 장점은 성능 저하 없이 메모리 안정성을 보장하는 거예요. 세부적으로 [소유권 개념(Ownership)](https://doc.rust-kr.org/ch04-00-understanding-ownership.html)은 자원 관리를 용이하게 하고, **데이터 경쟁 없는 동시성 기능**은 통해 멀티 스레드 환경에서도 보안성을 강화해줍니다. Python이나 JPMS(Java Platform Module System)와 일관된 모듈 관리, 캡슐화가 간편한 등, 언어 자체가 유연한 특성을 가지고 있으며 FFI(Foreign Function Interface)로 Java와 간편히 연결되는 것은 충분히 매력으로 다가옵니다.

EntanglementLib의 모든 보안 연산은 이 네이티브에서 수행되죠. 구체적으로 다음의 기능을 제공합니다.

- [X] 하드웨어 진난수, 혼합 난수, 양자난수(Quantum RNG) 생성
- [X] AEAD 암호화(ChaCha20)
- [X] 메모리 소거를 보장하는 보안 버퍼(Secure Buffer)
- [X] 상수-시간(Constant-Time) 연산
- [X] 해시(SHA2, SHA3, SHAKE 포함)

각 기능은 개별 크레이트로 분리되어 관리됩니다. 루트는 가상 매니페스트로 구성되어 있어 하위 크레이트를 관리하기 용이하죠. 또한 Java 측에서 이 네이티브를 사용할 때 잘못된 호출을 원천적으로 차단하기 위해 FFI 함수를 구현한 크레이트가 존재합니다. 이 크레이트는 Java 측에서 사용되어야 할 주요 함수를 전달하는 용도로 사용됩니다.

이 네이티브 라이브러리는 핵심 보안 기능 구현에 있어 외부 의존성(크레이트)을 사용하지 않습니다. 다르게 말해 외부로부터 들여오는 모든 자원을 기본적으로 신뢰하지 않는다는 겁니다. 이런 개발 철학은 **Zero Trust 원칙**을 지지하고, 이렇게 만들어진 하나의 결과물(얽힘 라이브러리)은 폐쇄 환경에서도 원활히 동작하게 됩니다. 이는 **Air-Gapped Ready 라는 원칙**에 부합합니다.

궁극적으로 이 네이티브는 엄격한 환경에서 자란 귀중한 자원으로서, 얽힘 라이브러리에서 적극적으로 안전하게 사용됩니다.

## 향후 계획

이 네이티브는 아직 갈 길이 멉니다. 지원되는 고전적 암호화 알고리즘 모듈을 다양하게 구현해야 합니다.

- [ ] AES(128, 192, 256)
- [ ] ARIA(128, 192, 256)
- [ ] RSA(2048, 4096, 8192)
- [ ] ED25519, ED448 서명
- [ ] X25519, X448 키 합의

이 뿐만 아니라 HMAC, HKDF 등의 암호학적 필수 기능도 제공되어야 합니다.

양자-내성 암호화(Post-Quantum Cryptography, PQC) 알고리즘은 다음의 목표를 가집니다.

- [ ] [FIPS 203(Module Lattice-based Key Encapsulate Mechanism, ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [ ] [FIPS 204(Module Lattice-based Digital Signature Algorithm, ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [ ] [FIPS 205(Stateless Hash-based Digital Signature Algorithm, SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)

위 PQC 알고리즘이 구현되면 다음의 TLS 기능도 제공되어야 합니다.

- [ ] TLS 1.3
- [ ] [`draft-ietf-tls-ecdhe-mlkem`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)에 따른 X25519MLKEM768

PKIX나 JWT 및 CWT, OTP 등, 아직 갈 길이 멀다는 것이 실감됩니다.

## 인증 및 규정 준수 필요

구현 뿐만이 아닙니다. 이 네이티브에서 구현되는 모든 기능은 국제적 인증 기관이 명시한 기능의 보안 구현(명세) 상황을 완전히 따라야 하고, 정식적인 인증을 받아야 합니다. 그 전까진 어떤 알고리즘도 '안전'하다고 판단하진 않습니다. 숨겨진 변수는 언제든 나타나기 마련이니까요.

따라서 이 네이티브의 모든 기능을 사용하신다면 반드시 '살험적(experimental)' 기능으로 제공하거나, 사용하시길 바랍니다.

> [!NOTE]
> 엄격한 인증 및 규정 심사를 통과한 기능은 즉각적으로 업데이트히겠습니다. [이 문서](COMPLIANCE.md)에서 해당 정보를 확인할 수 있도록 하겠습니다. 

# 영감 및 기여

마침 존경하는 보안 단체 `Legion of the BouncyCastle Inc`는 [`bc-rust`](https://github.com/bcgit/bc-rust/) 개발을 시작했고 얽힘 라이브러리 브릿징 기술에 유용할 법 한 영감을 많이 얻었습니다. 이들은 제가 얽힘 라이브러리 개발을 시작했을 때 부터 지금까지 언제나 저의 힘이 되어주고 있습니다. 어쨌든 저는 이 개발 속도를 유지할 것이며, 향후 업데이트에 따라 이 문서를 지속적으로 수정하겠습니다. 결국 이 목표를 향해 쭉 개발할 예정입니다.

> [!TIP]
> 여러분의 피드백은 언제나 아주 큰 힘이 됩니다. 이 프로젝트에 기여하고자 한다면 [이 곳](CONTRIBUTION.md)을 참고해주세요!

# 벤치마킹

이 네이티브 라이브러리의 벤치마킹은 `criterion` 크레이트를 통해 진행됩니다. 자세한 각 벤치마킹 결과는 [benchmarks 디렉토리 하위](benchmarks)에서 확인하실 수 있습니다.