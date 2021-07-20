use vrf_dalek::vrf::{SecretKey, VrfProof, PublicKey};

#[test]
fn check_output() {
    let alpha_string = b"test_rust_verification";
    let secret_key = SecretKey::from_bytes(&[202, 212, 14, 122, 235, 30, 33, 104, 227, 203, 102, 41, 233, 85, 135, 243, 230, 117, 114, 13, 113, 149, 37, 93, 232, 164, 196, 254, 170, 173, 84, 144]);
    let public_key = PublicKey::from_bytes(&[88, 54, 143, 167, 126, 198, 103, 217, 227, 175, 76, 235, 11, 244, 77, 180, 247, 74, 6, 2, 187, 59, 160, 128, 10, 44, 255, 181, 116, 45, 71, 153]);

    let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string[..]);

    let vrf_output = vrf_proof.verify(&public_key, &alpha_string[..]);
    assert!(vrf_output.is_ok());

    println!("Vrf output rust: {:?}", vrf_output.unwrap());
}
