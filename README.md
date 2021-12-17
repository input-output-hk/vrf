# Verifiable Random Function
**DISCLAIMER**: this crate is under active development and should not be used.

Implementation of the verifiable random function presented in 
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2, and that presented in
[draft-irtf-cfrg-vrf-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10) using
Edwards25519, SHA512, and Elligator2.

The goal of this crate is to  a compatible implementation with 
the VRF-03 [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium),
with the latest version of the standard, and with the batch-compatible 
version of the VRF, as presented in this [technical spec](https://iohk.io/en/research/library/papers/on-uc-secure-range-extension-and-batch-verification-for-ecvrf/).

#### Note on compatibility: 
Currently, the tests pass because we are using a [forked curve25519-dalek](https://github.com/iquerejeta/curve25519-dalek)
crate. The implementation of the vrf over libsodium differs in the elligator2
function. `curve25519-dalek`'s API does not allow us to modify the elligator2 
function, which makes use rely on a fork. In particular, [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/convert.c#L84)
we clear the sign bit, when it should be cleared only [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L2527)
(according to the latest standards).
This does not reduce the security of the scheme, but makes it incompatible with other
implementations. 

Similarly, the implementation of the `hash_to_curve` implementation in [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/pull/377)
is not compatible with the current version of the standard. This forces us to currently
stick to the `try-and-increment` version of the H2C function. While it provides the 
same security guarantees and efficiency, it does not provide compatibility with 
implementations that use the elligator function. We hope to the PR linked above, 
merged soon. 
