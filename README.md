# Verifiable Random Function
**DISCLAIMER**: this crate is under active development and should not be used.

Implementation of the verifiable random function presented in 
[draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) using
Edwards25519, SHA512, and Elligator2. 

The goal of this crate is to have (at least) a compatible implementation with 
the VRF-03 [implemented over libsodium](https://github.com/input-output-hk/libsodium/tree/draft-irtf-cfrg-vrf-03/src/libsodium).

## Minimal working example
To effectively run the tests comparing the VRF implementation and the libsodium
implementation, one needs to have libsodium compiled and installed. For that, 
run the following: 

```shell
git clone https://github.com/input-output-hk/libsodium.git libsodium_vrf
cd libsodium_vrf
./autogen.sh
./configure
make
make install
```

Then, we can compile and run the tests of this crate: 
```shell
make
```
The outputs of the vrf implementation and the libsodium implementation 
appear in the console. We can see they are the same. 

Currently, the tests pass because we are using the forked curve25519-dalek 
crate, as the implementations of the function `hash_to_curve` are not 
currently compatible, and curve25519-dalek's API does not allow us to modify
this function. 