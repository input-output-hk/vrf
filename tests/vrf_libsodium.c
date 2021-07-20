//
// Created by Inigo Querejeta Azurmendi on 20/7/21.
//

#include <stdio.h>
#include <sodium.h>

int main(void) {
    #define MESSAGE_LEN 22
    unsigned char message[MESSAGE_LEN] = "test_rust_verification";

    unsigned char pk[crypto_vrf_ietfdraft03_PUBLICKEYBYTES] = {88, 54, 143, 167, 126, 198, 103, 217, 227, 175, 76, 235, 11, 244, 77, 180, 247, 74, 6, 2, 187, 59, 160, 128, 10, 44, 255, 181, 116, 45, 71, 153};
    unsigned char sk[crypto_vrf_ietfdraft03_SECRETKEYBYTES] = {202, 212, 14, 122, 235, 30, 33, 104, 227, 203, 102, 41, 233, 85, 135, 243, 230, 117, 114, 13, 113, 149, 37, 93, 232, 164, 196, 254, 170, 173, 84, 144, 88, 54, 143, 167, 126, 198, 103, 217, 227, 175, 76, 235, 11, 244, 77, 180, 247, 74, 6, 2, 187, 59, 160, 128, 10, 44, 255, 181, 116, 45, 71, 153};

    unsigned char vrf_proof[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove(vrf_proof, sk, message, MESSAGE_LEN);

    unsigned char proof_output[crypto_vrf_ietfdraft03_OUTPUTBYTES];
    if (crypto_vrf_ietfdraft03_verify(proof_output, pk, vrf_proof, message, MESSAGE_LEN) == -1) {
        printf("verification failed");
    }


    printf("VRF output libsodium: ");
    for (int i = 0; i < crypto_vrf_ietfdraft03_OUTPUTBYTES; i++) {
        printf("%d ", proof_output[i]);
    }
    printf("\n");
}