# 얽힘 라이브러리: 네이티브 브릿지

> [이 라이브러리는 무슨 기능을 할까요?](INTRODUCTION.md) 기술에 대한 세부적 설명은 [퀀트 팀 공개 문서](https://docs.qu4nt.space/docs/projects/entanglementlib/entlib-native) 에서 확인할 수 있습니다.

[Rust의 소유권 개념](https://doc.rust-kr.org/ch04-00-understanding-ownership.html)은 저의 흥미를 유발하는 데 완벽하게 성공했고, 복합적인 Rust만의 특색있는 개발 방법(컴파일러의 메모리 안정성, 하드웨어 수준의 제어 등...)을 통해 [얽힘 라이브러리](https://github.com/Quant-Off/entanglementlib)를 안전하게 구현하는 데 목표를 두고자 했습니다.

얽힘 라이브러리 내에서 [Linker API (JEP389)](https://openjdk.org/jeps/389)를 사용하여 구현됩니다. 이 모듈은 전통적 방법이지만 어렵고 불안정한 JNI(Java Native Interface)로 네이티브 메소드 호출 작업을 수행하는 것을 넘어 코드와 데이터 복사 오버헤드 없이 Java와 Rust가 동일한 메모리 주소를 공유할 수 있도록 돕습니다.

> [이 문서](AGES.md)에서 최초 공개 버전부터 이 버전까지의 일대기를 확인하실 수 있습니다.

# 영감

마침 존경하는 보안 단체 `Legion of the BouncyCastle Inc`는 [`bc-rust`](https://github.com/bcgit/bc-rust/) 개발을 시작했고 얽힘 라이브러리 브릿징 기술에 유용할 법 한 영감을 많이 얻었습니다. 이들은 제가 얽힘 라이브러리 개발을 시작했을 때 부터 지금까지 언제나 저의 힘이 되어주고 있습니다.

어쨌든 저는 이 개발 속도를 유지할 것이며, 향후 업데이트에 따라 이 문서를 지속적으로 수정하겠습니다. 결국 이 목표를 향해 쭉 개발할 예정입니다. 그리고 언제든 피드백은 환영입니다.

# Alpha 버전

이 네이티브 라이브러리는 `1.1.0` 릴리즈 출시에 대한 준비를 마쳐도 곧바로 출시되진 않습니다. 이에 세밀하고 또 정밀하게 코드를 검토하고, 그 환경을 원활히 구축하기 위해 지금 이 시점에서 알파 버전으로 우선 공개하겠습니다.

# 벤치마킹

이 네이티브 라이브러리의 벤치마킹은 `criterion` 크레이트를 통해 진행됩니다. 자세한 각 벤치마킹 결과는 [benchmarks 디렉토리 하위](benchmarks)에서 확인하실 수 있습니다.