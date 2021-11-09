# Verifiable Random Function
**DISCLAIMER**: this crate is under active development and should not be used.

Implementation of the verifiable random function presented in 
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2, and that presented in
[draft-irtf-cfrg-vrf-09](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09) using
Edwards25519, SHA512, and Elligator2.

The goal of this crate is to  a compatible implementation with 
the VRF-03 [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium),
and with the latest version of the standard.

#### Note on compatibility: 
Currently, the tests pass because we are using a [forked curve25519-dalek](https://github.com/iquerejeta/curve25519-dalek)
crate. The implementation of the vrf over libsodium differs in the elligator2
function. `curve25519-dalek`'s API does not allow us to modify the elligator2 
function, which makes use rely on a fork. In particular, [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/convert.c#L84)
we clear the sign bit, when it should be cleared only [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L2527)
(according to the latest standards).
This does not reduce the security of the scheme, but makes it incompatible with other
implementations. 
