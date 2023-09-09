#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bn.h>


#define SIZE 4

int main() {
    unsigned char random1[SIZE], formatted[SIZE+2];
    BIGNUM *bn1 = BN_new();

    /*
    if (RAND_load_file("/dev/random", SIZE)!= SIZE){
        fprintf(stderr, "Error initializing the PRNG.\n");
    }
    RAND_bytes(random1, SIZE);*/

    BN_rand(bn1, 32, -1, 1);

    BN_print_fp(stdout, bn1);
    printf("\n");

    return 0;
}