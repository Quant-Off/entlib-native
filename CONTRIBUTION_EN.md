# Contribution and License

_Hello. We are Team Quant, and I am Quant Theodore Felix._

**We truly appreciate everyone who contributes to this project,** and we would like to inform you of a few prerequisites. First of all, this project follows the [`MIT LICENSE`](LICENSE).

Our team prioritizes **very strict security** and **efficient memory management** in conducting all projects. You can refer to [this project's security policy](SECURITY_EN.md). If you wish to contribute to this project, you must agree to the statement: "I am fundamentally committed to security in all code I write." Hereinafter, if you contribute, it will be considered that you fully agree to this statement.

To help you write code easily and quickly, and for us to actively reflect your changes, we have defined the following basic rules. These rules apply primarily to you, the contributors, and again to us who handle the merge operations. We apologize for any inconvenience this may cause. **However, we have a deep belief in very strict security rules, and we ask for your understanding.**

## Contribution Rules

1. You can write Rust-based code. Please keep in mind that this code is called via the [FFM API](https://openjdk.org/jeps/454) from the [Entanglement Library](https://github.com/Quant-Off/entanglementlib/blob/master/README_EN.md). This means that the code written must be observable in parts accessible from that library. This directly leads to the meaning of "encapsulation of precise implementation". Please **clearly encapsulate the parts that can be exposed as APIs and the internal implementations**.
2. Basically, we expect and anticipate **active testing**. This simply means that **very clear tests must exist** for the features you write. As you know, tests are very helpful not only for project development but also for **understanding the code you wrote**. Please write clear tests on how the written function should behave and how it behaves in special cases (edge cases). **You might even discover very critical vulnerabilities in tests!**
3. Also, we would like to inform you about benchmarking. This project uses the `Criterion` crate to conduct benchmarking, and the results are clearly recorded under [benchmarks/](benchmarks). However, you do not need to organize the results of your benchmarking in related documents! Anyway, the benchmarking we conduct is generally divided into "security" and "throughput" evaluations. We hope you also write benchmarking code in a consistent style. **And we would like to say that this is not mandatory!**

You might be writing **code for a vast amount of special security features that fully fall under the above rules**, or you might simply want to fix simple optimizations, bugs, `docstring`s, or typos in documentation. In cases deemed as simple changes, you **do not need to strictly follow** the above rules.

To be more specific, the above rules apply only if your code involves **external visibility**, **definition of members such as functions and variables**, or **changes to existing features**. To prepare for sudden errors, we will carefully review such changes.

There are quite special cases. **If you wish to add or modify workflows, please be sure to let us know via issues.** This is because there is a risk of confusion.

## Please Contribute Comfortably

We also know that the contribution standards for this project are quite high. **However, we want to clearly state that this does not mean "If your code does not meet these rules, we will not use it."**

We are not an organization that evaluates like a machine whether your feedback is big, small, important, necessary, or meaningful. **What is important is that you plant your individual philosophy into this code**, and we are **extremely grateful just for you sharing your thoughts on the code!** What we want to say is that **we basically feel gratitude for you reviewing this code in any way**.

We hope you do not stop interacting with this project due to annoying rules. **If you feel burdened in reviewing this code, we believe that this project has no value of existence.**

We would appreciate it if you recognize that our team prepares for possible scenarios in terms of security and envisions a future where we do this together with everyone!

# Easy Access and Direction

The above rules might just be an eyesore. If you fall into one of the following categories, do not hesitate! **We use the concept of "Levels" for easy contribution.** Let's categorize your contribution through this.

- `LEVEL 1` - **Very, very simple**
  - Are there errors (strange grammar, typos, omissions, etc.) in the Markdown documents (`.md`)?
  - Is there necessary information (technical specifications, usage instructions, etc.)?
  - Do you have ideas for necessary features? 
- `LEVEL 2` - **Complex at times**
  - Does there seem to be a problem with the test code (wrong references, no handling for specific situations, etc.)?
  - Do you have ideas for workflows? **<<= In this case, please leave it via issues!**
  - Does the benchmarking seem wrong, or do you need additional benchmarking data?
  - Do you have ideas for feature encapsulation?
  - Does there seem to be a problem with values calculated through cryptographic operations (mismatch with expected values, logic different from operations specified in technical specifications, etc.)?
- `LEVEL 3` - **Looks very serious**
  - Does the logic seem different from what is described in NIST's `FIPS`, `SP`, or `IG`?
  - Have you discovered a serious security vulnerability? **<<= In this case, please be sure to let us know at <qtfelix@qu4nt.space>!**
  - Do you have opinions on data erasure, its method, or the currently implemented logic?
  - **Do you judge that the security of the overall security logic currently implemented is not rigorous?**

You can contact us in any way regarding the above content (with the exception of specific items).

You can use email <qtfelix@qu4nt.space> or Discord `qtfelix`.