#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bn.h>


#define SIZE 4

int main() {
    unsigned char random1[SIZE], random2[SIZE];
    BIGNUM *bn1 = BN_new(), *bn2 = BN_new(), *result = BN_new(), *modulus = BN_new(), *base = BN_new(), *exp = BN_new();
    BN_CTX * ctx = BN_CTX_new();

    //Seeding the PRNG
    if (RAND_load_file("/dev/random", 64)!= 64){
        fprintf(stderr, "Error initializing the PRNG.\n");
    }

    //Generating 2 random 32 bit integers
    RAND_bytes(random1, SIZE);
    BN_bin2bn(random1, SIZE, bn1);
    RAND_bytes(random2, SIZE);
    BN_bin2bn(random2, SIZE, bn2);

    printf("First random int32: %s\nSecond random int32: %s\n", BN_bn2dec(bn1), BN_bn2dec(bn2));

    //Setting base and exponent
    BN_set_word(base, 2);
    BN_set_word(exp, 32);

    //Calculating the modulus
    BN_exp(modulus, base, exp, ctx);

    //Computing random1 * random2 mod 2^32
    BN_mod_mul(result, bn1, bn2, modulus, ctx);
    printf("Result: %s\n", BN_bn2dec(result));
    
    return 0;
}