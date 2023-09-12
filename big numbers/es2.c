#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MODULUS_SIZE 3072
#define EXP_SIZE 256

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
    if(RAND_load_file("/dev/random", 64) != 64) handle_errors();

    /* READ: https://www.ietf.org/rfc/rfc3526.txt */

    BIGNUM *p = BN_new(), *alice_choice = BN_new(), *bob_choice = BN_new(), *g = BN_new();
    BIGNUM *A = BN_new(), *B = BN_new(), *s_alice = BN_new(), *s_bob = BN_new();

    //Setting g, in practise is usually a small integer like 2, 3, ...
    BN_set_word(g, 5);

    //Initializing ctx for intermediate calculus
    BN_CTX *ctx = BN_CTX_new();

    //Generating a prime number p
    while(BN_check_prime(p, ctx, NULL) != 1) {
        BN_rand(p, MODULUS_SIZE, 0, 1);
    }

    if(!BN_check_prime(p, ctx, NULL)) {
        fprintf(stderr, "Error generating random prime modulus.\n");
        abort();
    } else {
        printf("Shared prime modulus p:\n");
        BN_print_fp(stdout, p);
        printf("\n\n");
    }

    //Generating Alice and Bob secret choices
    if(!BN_rand(alice_choice, EXP_SIZE, -1, 0)) handle_errors();
    if(!BN_rand(bob_choice, EXP_SIZE, -1, 0)) handle_errors();

    printf("Alice secret choice:   ");
    BN_print_fp(stdout, alice_choice);
    printf("\nBob secret choice:   ");
    BN_print_fp(stdout, bob_choice);
    printf("\n");

    //Alice calculates and send to Bob 'A = g^a mod p'
    printf("\nAlice calculates and send to Bob 'A = g^a mod p':\n");
    BN_mod_exp(A, g, alice_choice, p, ctx);
    BN_print_fp(stdout, A);
    printf("\n");

    //Bob calculates and send to Alice 'B = g^b mod p'
    printf("\nBob calculates and send to Alice 'B = g^b mod p':\n");
    BN_mod_exp(B, g, bob_choice, p, ctx);
    BN_print_fp(stdout, B);
    printf("\n");

    //Alice calculates 's = B^a mod p'
    printf("\nAlice computes the secret key 's = B^a mod p':\n");
    BN_mod_exp(s_alice, B, alice_choice, p, ctx);
    BN_print_fp(stdout, s_alice);
    printf("\n");

    //Bob calculates 's = A^b mod p'
    printf("\nBob computes the secret key 's = A^b mod p':\n");
    BN_mod_exp(s_bob, A, bob_choice, p, ctx);
    BN_print_fp(stdout, s_bob);
    printf("\n");

    //The keys calculated by Alice and Bob should be the same. Let's check it
    if(BN_cmp(s_alice, s_bob) == 0) {
        printf("\n\nAlice's key and Bob's key are equal. Successfull DH key agreement.\n");
    } else {
        printf("\n\nSomething goes wrong. The Alice'key should be equal to the Bob's key.\n");
        abort();
    }

    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(alice_choice);
    BN_free(bob_choice);
    BN_free(g);
    BN_free(A);
    BN_free(B);
    BN_free(s_alice);
    BN_free(s_bob);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}