# In Early Public Versions

> [Korean AGES](AGES.md)

Initially, this Rust native bridge module was prepared to enhance the `Project Panama API`-based native key management feature ([`EntLibCryptoKey.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto/key/EntLibCryptoKey.java)) first implemented in the [Entanglement Library's BouncyCastle low-level API branch](https://github.com/Quant-Off/entanglementlib/tree/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/experimental/crypto). This was because we wanted to enhance security and efficiency by handling management and erasure functions in Off-Heap rather than Heap.

And that feature was successfully released as the [Sensitive Data Container](https://docs.qu4nt.space/en/docs/projects/entanglementlib/sensitive-data-container) feature in the `EntanglementLib 1.1.0` release. Specifically, erasure logic was implemented in this native library using the `zeroize` crate. Accordingly, we succeeded in successfully optimizing and enhancing quite messy classes like [`KeyDestroyHelper.java`](https://github.com/Quant-Off/entanglementlib/blob/exp-bc-lightweight-api/src/main/java/space/qu4nt/entanglementlib/security/KeyDestroyHelper.java) that existed in the initial release of the Entanglement Library.

However, a few problems arose. It can be said that the core of the Entanglement Library was pulling many security features from external libraries (dependencies). Among them, the `BouncyCastle` dependency was responsible for the internal logic for all algorithms provided by the Entanglement Library. While releasing the latest release, I mentioned in the TODO that I would reduce dependencies, and I wanted to build the features of the native bridge one by one, but I ran into the paradoxical problem that I had to use external dependencies again to implement the necessary features on the Rust side. It would probably take quite a while to implement all those features alone.

Therefore, while implementing the native bridge, I initially held the belief that 'necessary features should actively use dependencies (crates), but they must meet the core philosophy of "military-grade security".' However, using external dependencies greatly harmed my freedom more than I thought. It's not that it's unsafe, but the biggest issue was the difficulty in implementing features that fit perfectly into the Entanglement Library.

I wanted to discard trivial thoughts and focus on security, and to achieve this wish, I started developing the `1.1.0` release shortly after the `1.0.0` release. You might think that bumping up a version is no big deal, but my thoughts are quite different.

# In the Next Release

Now, the Entanglement Library begins preparations to have very, very strict security logic. In this native library, logic with core security philosophies such as military-grade and large-scale enterprise will all be reborn.

Core logic such as `Base64` encoding/decoding, simple constant-time bitwise operations, random number generation, and classical encryption algorithms will be developed without external dependencies. I hope that by developing logic with a simple but precise flow, it will be used in many infrastructure securities, but it is a pity that I do not have much speaking ability.

As you know, the native library of the `1.0.0` release was very messy, and although security was enhanced, it was not optimized at all. The SLH-DSA algorithm implementation, which was in the midst of ACVP certification, was also written poorly and was just chaos itself. Therefore, to optimize features and overhaul the code that has quite a few problems, I intend to virtualize the root manifest and bridge it with the Entanglement Library.

The `1.1.0` release (or higher releases) of the native library will have very large changes like the `1.1.0` update of the Entanglement Library. Naturally, there will be large changes in the Entanglement Library following the large changes. Once the release is launched like that, both libraries will have the very same release version.