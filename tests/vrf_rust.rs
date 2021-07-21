use vrf_dalek::vrf::{PublicKey, SecretKey, VrfProof};

#[test]
fn check_output() {
    let alpha_string = b"test_rust_verification";
    let secret_key = SecretKey::from_bytes(&[
        202, 212, 14, 122, 235, 30, 33, 104, 227, 203, 102, 41, 233, 85, 135, 243, 230, 117, 114,
        13, 113, 149, 37, 93, 232, 164, 196, 254, 170, 173, 84, 144,
    ]);
    let public_key = PublicKey::from_bytes(&[
        88, 54, 143, 167, 126, 198, 103, 217, 227, 175, 76, 235, 11, 244, 77, 180, 247, 74, 6, 2,
        187, 59, 160, 128, 10, 44, 255, 181, 116, 45, 71, 153,
    ]);

    let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string[..]);

    let vrf_output = vrf_proof.verify(&public_key, &alpha_string[..]);
    assert!(vrf_output.is_ok());

    let libsodium_generated_output: [u8; 64] = [
        12, 95, 188, 171, 151, 171, 15, 102, 194, 78, 160, 215, 180, 33, 205, 15, 177, 49, 94, 233,
        233, 213, 176, 190, 64, 194, 124, 119, 160, 54, 254, 119, 37, 168, 244, 104, 141, 220, 77,
        34, 109, 14, 169, 102, 51, 123, 0, 25, 102, 18, 230, 157, 107, 120, 9, 60, 50, 120, 192,
        169, 230, 193, 112, 76,
    ];
    let rust_output = vrf_output.unwrap();

    assert_eq!(rust_output, libsodium_generated_output);
    println!("Vrf output rust: {:?}", rust_output);
}
