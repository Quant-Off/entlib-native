# 얽힘 라이브러리: 네이티브 브릿지

[Rust의 소유권 개념](https://doc.rust-kr.org/ch04-00-understanding-ownership.html)은 저의 흥미를 유발하는 데 완벽하게 성공했고, 복합적인 Rust만의 특색있는 개발 방법(컴파일러의 메모리 안정성, 하드웨어 수준의 제어 등...)을 통해 [얽힘 라이브러리](https://github.com/Quant-Off/entanglementlib)를 안전하게 구현하는 데 목표를 두고자 했습니다.

이 Rust 네이티브 브릿지 모듈은 [얽힘 라이브러리의 BouncyCastle low-level API 브랜치](https://github.com/Quant-Off/entanglementlib/tree/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto)에서 첫 구현된 `Project Panama API` 기반 네이티브 키 관리 기능([`EntLibCryptoKey.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto/key/EntLibCryptoKey.java))을 강화하기 위해 마련됐습니다. 

이 기능은 `EntanglementLib 1.1.0` 릴리즈에서 [민감 데이터 컨테이너](https://docs.qu4nt.space/docs/projects/entanglementlib/sensitive-data-container)기능으로 강화되어 성공적으로 출시되었습니다. 구체적으로, 이 네이티브 라이브러리에 `zeroize` 크레이트를 사용하여 소거 로직이 구현되었었습니다.

얽힘 라이브러리 초기 릴리즈에 존재하던 [`KeyDestroyHelper.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/security/KeyDestroyHelper.java)와 같은 꽤 난잡한 클래스들을 뜯어고쳐 성공적으로 최적화하고 강화하는 데 성공했고, 얽힘 라이브러리 내에서 [Linker API (JEP389)](https://openjdk.org/jeps/389)를 사용하여 구현됩니다. 이 모듈은 전통적 방법이지만 어렵고 불안정한 JNI(Java Native Interface)로 네이티브 메소드 호출 작업을 수행하는 것을 넘어 코드와 데이터 복사 오버헤드 없이 Java와 Rust가 동일한 메모리 주소를 공유할 수 있도록 돕습니다.

# 다음 릴리즈에서

사실, `1.0.0` 릴리즈의 네이티브 라이브러리는 매우 난잡했으며, 보안성 강화는 되었으나 최적화되지 않았었습니다. ACVP 인증에 한참이던 SLH-DSA 알고리즘 구현도 볼품없이 작성되어 그냥 혼돈 그 자체인 코드였습니다. 따라서, 기능을 최적화할 겸 꽤 문제가 많은 코드를 엎어버리고 루트를 가상 매니페스트화하여 얽힘 라이브러리와 브릿징하려고 합니다.

네이티브 라이브러리의 `1.1.0` 릴리즈는 얽힘 라이브러리의 `1.1.0` 업데이트 처럼 아주 큰 변화를 가질 예정이며, 큰 변경에 따라 얽힘 라이브러리에도 큰 변화가 있을 예정입니다. 그렇게 릴리즈를 출시하고 나면, 두 라이브러리 모두 매우 정식적인 `1.1.0` 릴리즈를 가지게 됩니다.

마침 존경하는 `Legion of the BouncyCastle Inc`는 [`bc-rust`](https://github.com/bcgit/bc-rust/) 개발을 시작했고 얽힘 라이브러리에 대해 매우 유용한 영감을 얻었습니다. 제 이슈나 PR을 읽어주진 않고 계시지만, 네... 그럼에도 불구하고 BC는 언제나 저의 힘이 되어주고 있습니다. 

어쨌든 저는 이 개발 속도를 유지할 것이며, 향후 업데이트에 따라 이 문서를 지속적으로 수정하겠습니다. 결국 이 목표를 향해 쭉 개발할 예정입니다. 그리고 언제든 피드백은 환영입니다.

# Alpha 버전

따라서 이 네이티브 라이브러리는 `1.1.0`으로 곧바로 출시되기 전의 몇 가지 안정적인 준비를 하기 위해 알파 버전으로 공개됩니다. 이 버전에서 