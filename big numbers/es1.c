#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define ENCRYPT 1
#define DECRYPT 0

#define SIZE 32

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    //Loading all the error strings
    ERR_load_crypto_strings();
    //Loading all the algorithms
    OpenSSL_add_all_algorithms();

    //Seeding PRNG
    if(RAND_load_file("/dev/random", 32) != 32) handle_errors(); 

    unsigned char rand1[SIZE], rand2[SIZE], rand3[SIZE];

    //Generating random string
    if(!RAND_bytes(rand1, SIZE)) handle_errors();
    if(!RAND_bytes(rand2, SIZE)) handle_errors();
    if(!RAND_bytes(rand3, SIZE)) handle_errors();

    //Converting random string into big numbers
    BIGNUM *bn1 = BN_new(), *bn2 = BN_new(), *bn3 = BN_new(), *result = BN_new(), *temp = BN_new();
    BN_bin2bn(rand1, SIZE, bn1);
    BN_bin2bn(rand2, SIZE, bn2);
    BN_bin2bn(rand3, SIZE, bn3);

    printf("Generated big numbers:\n");
    printf("bn1:    ");
    if(!BN_print_fp(stdout, bn1) == 1) handle_errors();
    printf("\n");
    printf("bn2:    ");
    if(!BN_print_fp(stdout, bn2) == 1) handle_errors();
    printf("\n");
    printf("bn3:    ");
    if(!BN_print_fp(stdout, bn3) == 1) handle_errors();
    printf("\n\n\n");

    //Defining context, used for intermediate operations
    BN_CTX *ctx = BN_CTX_new();

    //Computing operations
    printf("Computing operations:\n\n");

    //1) sum(bn1+bn2)
    if(!BN_add(result, bn1, bn2) == 1) handle_errors();
    printf("sum(bn1+bn2) : ");
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    //2) difference(bn1-bn3)
    printf("difference(bn1-bn3) :");
    if(!BN_sub(result, bn1, bn3) == 1) handle_errors();
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    //3) multiplication(bn1*bn2*bn3)
    printf("multiplication(bn1*bn2*bn3) :");
    if(!BN_mul(temp, bn1, bn2, ctx) == 1) handle_errors();
    if(!BN_mul(result, temp, bn3, ctx) == 1) handle_errors();
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    //4) integer division(bn3/bn1)
    printf("integer division(bn3/bn1) :");
    if(!BN_div(result, temp, bn3, bn1, ctx) == 1) handle_errors();
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    //5) modulus(bn1 mod bn2)
    printf("modulus(bn1 mod bn2) :");
    if(!BN_mod(result, bn1, bn2, ctx) == 1) handle_errors();
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    //6) modulus exponentiation (bn1^bn3 mod bn2)
    printf("modulus exponentiation (bn1^bn3 mod bn2) :");
    if(!BN_mod_exp(result, bn1, bn3, bn2, ctx) == 1) handle_errors();
    if(!BN_print_fp(stdout, result) == 1) handle_errors();
    printf("\n\n");

    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    BN_free(result);
    BN_free(temp);
    BN_CTX_free(ctx);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}