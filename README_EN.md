# EntanglementLib: Native Bridge

> [Korean README](README.md)

> [What does this library do?](INTRODUCTION.md) Detailed technical explanations can be found in the [Quant Team Public Documentation](https://docs.qu4nt.space/en/docs/projects/entanglementlib/entlib-native).

[Rust's concept of ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html) succeeded perfectly in sparking my interest, and I aimed to safely implement the [EntanglementLib](https://github.com/Quant-Off/entanglementlib/blob/master/README_EN.md) through complex development methods unique to Rust (compiler's memory safety, hardware-level control, etc...).

It is implemented using the [Linker API (JEP389)](https://openjdk.org/jeps/389) within the EntanglementLib. This module goes beyond performing native method calls with the traditional but difficult and unstable JNI (Java Native Interface) and helps Java and Rust share the same memory address without code and data copy overhead.

> You can check the history from the first public version to this version in [this document](AGES_EN.md).

# Inspiration and Contribution

Just in time, the respected security organization `Legion of the BouncyCastle Inc` started developing [`bc-rust`](https://github.com/bcgit/bc-rust/), and I got a lot of inspiration that would be useful for the EntanglementLib bridging technology. They have always been my strength from when I started developing the EntanglementLib until now. Anyway, I will maintain this development speed and continuously modify this document according to future updates. Eventually, I plan to continue developing towards this goal.

> [!TIP]
> Your feedback is always a great strength. If you wish to contribute to this project, please refer to [here](CONTRIBUTION_EN.md)!

# Alpha Version

This native library will not be released immediately even if preparations for the `1.1.0` release are completed. Therefore, to review the code in detail and precisely, and to smoothly build that environment, I will first release it as an alpha version at this point.

# Benchmarking

Benchmarking of this native library is conducted through the `criterion` crate. Detailed results of each benchmark can be found under the [benchmarks directory](benchmarks).