# 초기 공개 버전들에서

> [English AGES](AGES_EN.md)

초기에 이 Rust 네이티브 브릿지 모듈은 [얽힘 라이브러리의 BouncyCastle low-level API 브랜치](https://github.com/Quant-Off/entanglementlib/tree/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto)에서 첫 구현된 `Project Panama API` 기반 네이티브 키 관리 기능([`EntLibCryptoKey.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto/key/EntLibCryptoKey.java))을 강화하기 위해 마련됐습니다. 관리 및 소거 기능을 Heap이 아닌 Off-Heap에서 처리하여 보안 및 효율을 강화하고자 했기 때문입니다.

그리고 해당 기능은 `EntanglementLib 1.1.0` 릴리즈에서 [민감 데이터 컨테이너](https://docs.qu4nt.space/docs/projects/entanglementlib/sensitive-data-container)기능으로 강화되어 성공적으로 출시되었습니다. 구체적으로, 이 네이티브 라이브러리에 `zeroize` 크레이트를 사용하여 소거 로직이 구현되었었습니다. 이에 얽힘 라이브러리 초기 릴리즈에 존재하던 [`KeyDestroyHelper.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/security/KeyDestroyHelper.java)와 같은 꽤 난잡한 클래스들을 뜯어고쳐 성공적으로 최적화하고 강화하는 데 성공했습니다.

다만 몇 가지 문제가 발생합니다. 얽힘 라이브러리는 외부 라이브러리(의존성)로부터 많은 보안 기능을 끌어 쓰고 있었던 것이 핵심이라 할 수 있습니다. 그 중에서도 `BouncyCastle`의존성은 얽힘 라이브러리에서 제공하는 모든 알고리즘에 대해 내부 로직을 책임졌습니다. 최신 릴리즈를 공개함과 동시에 TODO를 통해 의존성을 줄이겠다 언급했고, 네이티브 브릿지의 기능을 하나씩 만들어나가고자 했습니다만, Rust 측에서 필요한 기능을 구현하려면 또 다시 외부 의존성을 사용해야 한다는 역설적 문제에 부딪혔습니다. 아무래도 혼자 그 많은 기능을 구현하는 데에는 꽤 시간이 들 테니까요.

따라서 네이티브 브릿지를 구현하며 우선적으로 '필요한 기능은 의존성(크레이트)을 적극적으로 사용하되, 핵심 철학인 "군사적 보안"에 미치게끔 해야 한다.' 라는 신념을 가지기도 했습니다만, 외부 의존성 사용은 생각보다 저의 자유를 크게 해쳤습니다. 안전하지 않은 것이 아닙니다만, 얽힘 라이브러리에 딱 틀어맞는 기능을 구현하는 데 애먹었은게 가장 큽니다.

잔가지 생각들은 버리고 보안에 전념하고 싶었고, 이 바램을 이루기 위해 `1.0.0` 공개 후 얼마 안 가 `1.1.0` 릴리즈 개발을 시작했습니다. 버전 하나 올리는게 대수라고 생각하실 수도 있지만 제 생각은 꽤 다릅니다.

# 다음 릴리즈에서

이제 얽힘 라이브러리는 매우매우 엄격한 보안 로직을 갖출 준비를 시작합니다. 이 네이티브 라이브러리에선 군사급, 대규모 엔터프라이즈 등 핵심 보안 철학을 가진 로직이 모두 재탄생됩니다.

`Base64` 인/디코딩이나 단순 상수-시간 비트 연산, 난수 생성, 고전 암호화 알고리즘 등의 핵심 로직들을 외부 의존성 없이 개발합니다. 단순하지만 정밀한 흐름을 가진 로직을 개발함으로써 많은 인프라 보안에 사용되었으면 좋겠습니다만, 저는 딱히 말하는 능력이 있진 않아 아쉽습니다.

아시다시피 `1.0.0` 릴리즈의 네이티브 라이브러리는 매우 난잡했으며, 일단 보안성 강화는 되었으나 모두 최적화되지 않았었죠. ACVP 인증에 한참이던 SLH-DSA 알고리즘 구현도 볼품없이 작성되어 그냥 혼돈 그 자체인 코드였습니다. 따라서, 기능을 최적화할 겸 꽤 문제가 많은 코드를 엎어버리고, 루트를 가상 매니페스트(virtual manifest)화하여 얽힘 라이브러리와 브릿징하려고 합니다.

네이티브 라이브러리의 `1.1.0` 릴리즈(또는 그 이상의 릴리즈)는 얽힘 라이브러리의 `1.1.0` 업데이트 처럼 아주 큰 변화를 가질 예정입니다. 큰 변경에 따라 자연스럽게 얽힘 라이브러리에도 큰 변화가 있을 예정입니다. 그렇게 릴리즈를 출시하고 나면, 두 라이브러리 모두 매우 같은 릴리즈 버전을 가지게 됩니다.