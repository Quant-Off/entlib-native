# Contribution and License

> [Korean CONTRIBUTION](CONTRIBUTION.md)

_Hello. We are Team Quant, and I am Quant Theodore Felix._

**Thank you very much to everyone who contributes to this project.** I would like to inform you of a few preliminary preparations. First of all, please understand that this project follows the [`MIT LICENSE`](LICENSE), but the parent project, "Entanglement Library," follows the `PolyForm Noncommercial License 1.0.0`, so it is not free from commercial (economic) use. In summary, the following uses are possible:

- **Allowed**: Learning, personal projects, non-profit research, internal use for educational purposes, etc.
- **Prohibited**: Direct sales, use within commercial services, business use within a for-profit company, etc.

Our team emphasizes **very strict security** and **efficient memory management** in all our projects. You can refer to [this project's security policy](SECURITY_EN.md).

Before contributing to this project, please ask yourself, **"Is the code I'm writing faithful to security?"** in accordance with the security philosophy of the Entanglement Library.

## Contribution Rules

We have defined the following basic rules to help you write code easily and quickly and to actively incorporate your changes. These rules apply to both maintainers and contributors.

1. You can write code based on Rust, C/C++. The important thing to keep in mind here is the **implementation for the FFI boundary communication standard**. In other words, the code you write must have a strict distinction (encapsulation) between the parts accessible from the outside and the parts where core operations are performed.
2. Basically, we expect **active testing**. This simply means that **there must be clear tests for the features you write**. Testing not only helps the project develop, but it also **greatly helps you understand the code you've written.** Please write clear tests for how the feature you've written should work and how it works in special cases (edge cases). **You can also find very critical vulnerabilities in testing!**
3. And I want to tell you about benchmarking. This project uses the `Criterion` crate to perform benchmarking and records the results clearly under [benchmarks/](benchmarks). The benchmarking of `entlib-native` is divided into performance evaluations of "security" and "throughput". (This is not mandatory!)

You can **write a very large amount of code for special security features that fully correspond to the above rules**, or you may find and want to fix problems such as simple optimizations, bugs, `docstring` and document typos. If you judge it to be a simple change, you **do not need to strictly follow the above rules.**

To be more specific, the above rules only apply if the code you write includes **visibility from the outside**, **definition of members such as functions and variables**, and **changes to existing features**. We will review the changes carefully to prepare for sudden errors.

In a rather special case, **if you want to add or modify a workflow (or discuss ideas), please be sure to let us know as a `Level 2` (see below) issue.** This is because there is a risk of confusion.

## Feel Free to Contribute

We are also aware that the contribution threshold is quite high. **However, I want to make it clear that this does not mean "we will not use your code if it does not meet these rules."**

We are not an organization that evaluates your feedback like a machine, whether it is big, small, important, necessary, or meaningful. **What is important is that you instill your individual philosophy into this code**, and we are very grateful just for you to **share your thoughts on the code!** What we want to say is that **we are basically grateful for you reviewing this code in any way.**

We hope you don't stop interacting with this project because of annoying rules. **We believe that this project has no reason to exist if you feel burdened to review this code.**

We would appreciate it if you would know that our team is preparing for as many numbers as possible in terms of security and is drawing a future where we do that action with everyone.

# Easy Access and Direction

The above rules may just be an eyesore. If any of the following apply, you don't have to hesitate! **We use the concept of "levels" for easy contribution.** Let's break down your contributions through this.

- `LEVEL 1` - **Very, very simple**
  - Is there an error (strange grammar, typo, omission, etc.) in the content of the markdown document (`.md`)?
  - Is there any necessary information (technical specifications, feature usage, etc.)?
  - Do you have an idea for a necessary feature?
- `LEVEL 2` - **Complex at times**
  - Does there seem to be a problem with the test code (wrong reference, no handling of a specific situation, etc.)?
  - Do you have an idea for a workflow? **<<= In this case, please leave it as an issue!**
  - Does the benchmarking seem wrong, or do you need additional benchmarking data?
  - Do you have an idea for feature encapsulation?
  - Does there seem to be a problem with the value calculated through cryptographic operations (does not match the expected value, different logic from the operation specified in the technical specification, etc.)?
- `LEVEL 3` - **Looks very serious**
  - Does it seem to be a different logic from what is described in NIST's `FIPS`, `SP`, or `IG`?
  - Have you found a serious security vulnerability? **<<= In this case, please be sure to let us know at <qtfelix@qu4nt.space>!**
  - Do you have an opinion on the method or currently implemented logic for data erasure?
  - **Do you judge that the security of the overall security logic currently implemented is not strict?**

# Major Contributions Based on the Latest Release Update Criteria

Contributions corresponding to the following items for this project are classified as `Level 3` and are reviewed with the highest priority (of course, security contributions are the 0th priority).

- Common
  - **Correct error propagation method**: The core function of many crates returns a `SecureBuffer` struct and a string reference through a `Result` enum. This is inappropriate for error propagation.
  - **Compliance issues**: If you find any parts that do not comply with international certifications and regulations in the implementation of the cryptographic module, please contact us immediately.
  - **Error messages**: Error messages should be ambiguous by default, but they must be truthful enough to be subtly recognizable. What do you think of the current error messages?
- Secure buffer crate `entlib-native-secure-buffer`
  - **Bare-metal cache flush issue**: When falling back for a no_std closed environment in `zeroizer.rs`, it is said that cache line flushing may not be guaranteed depending on the hardware (CPU) characteristics of the environment. Delicate evaluation and verification are needed for this part.
  - **Double lock**: When interacting through the JO (Java-Owned) pattern, the memory is locked and then transmitted. The `SecureMemoryBlock` struct on the Rust side performs another lock on this data. What do you think about this operation?
  - **Bare-metal support**: Most modern IoT, HSM, and automotive systems run on ARM-based bare-metal or RTOS environments. Currently, the secure buffer uses system calls like `mlock` to lock memory, but such responses are impossible in bare-metal environments. We need ideas for "possible responses" at the software level.
- CI workflow
  - **Strict constant-time check**: Do you think the currently implemented constant-time operation is insufficient, or what do you think should be done for strict verification?
  - **How to track memory corruption**: Level 3 (binary memory corruption tracking) of the CC constant-time audit workflow uses Valgrind to perform tests in a Unix environment. However, I have temporarily disabled it because I don't have a big idea about this part yet. Please let me know if you have a good idea about this.

# Contact

You can contact us in any way regarding the above (except for certain items).

You can use email <qtfelix@qu4nt.space> or Discord `qtfelix`.