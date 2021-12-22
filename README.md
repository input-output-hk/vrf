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

## Benchmarks
We ran our benchmarks using `RUSTFLAGS='-C target-cpu=native' cargo bench` with 
an `Intel Core i7 @ 2,7 GHz`. We run the benchmarks with and without the feature
`batch_deterministic`.

Using deterministic batching
```
VRF10/Generation        time:   [151.86 us 154.50 us 157.65 us]
VRF10/Verification      time:   [112.43 us 114.26 us 116.30 us]

VRF10 Batch Compat/Generation
                        time:   [149.78 us 153.94 us 158.98 us]
VRF10 Batch Compat/Single Verification
                        time:   [115.58 us 118.88 us 122.64 us]               
VRF10 Batch Compat/Batch Verification/32
                        time:   [2.8448 ms 2.8590 ms 3.0307 ms]
VRF10 Batch Compat/Batch Verification/64
                        time:   [5.2697 ms 5.3886 ms 5.5184 ms]
VRF10 Batch Compat/Batch Verification/128
                        time:   [9.7886 ms 9.4337 ms 10.226 ms]
VRF10 Batch Compat/Batch Verification/256
                        time:   [19.332 ms 17.856 ms 20.228 ms]
VRF10 Batch Compat/Batch Verification/512
                        time:   [37.447 ms 35.341 ms 39.251 ms]
VRF10 Batch Compat/Batch Verification/1024
                        time:   [72.113 ms 69.364 ms 75.462 ms]
```

Using random batching
```
VRF10 Batch Compat/Batch Verification/32
                        time:   [2.3848 ms 2.3904 ms 2.3964 ms]
VRF10 Batch Compat/Batch Verification/64
                        time:   [4.3754 ms 4.4000 ms 4.4309 ms]
VRF10 Batch Compat/Batch Verification/128
                        time:   [8.5777 ms 8.7975 ms 9.0524 ms]
VRF10 Batch Compat/Batch Verification/256
                        time:   [15.807 ms 15.878 ms 15.955 ms]
VRF10 Batch Compat/Batch Verification/512
                        time:   [29.507 ms 29.605 ms 29.712 ms]
VRF10 Batch Compat/Batch Verification/1024
                        time:   [57.788 ms 58.080 ms 58.412 ms]
```


Translated into cost of a single verification (time in us)

|Size| Deterministic | Non-deterministic | 
|:----: | :----: | :----: |
|1 | 118.88 | 118.88 |
|32 | 89 |75 |
| 64 | 84 | 69 |
|128 | 74 | 69| 
| 256 | 70 | 62 |
| 512 | 69 | 58|
| 1024 | 67 | 56 |

Using non-deterministic batching we can reduce to 0.6 the time per verification
with batches of 64, and 0.47 with batches of 1024. Using deterministic batching
the times are slightly worse, as we need to compute two additional hashes for each 
proof verified. We reduce the time per verification to 0.71 with batches of 64 
and up to 0.56 with batches of 1024. 
