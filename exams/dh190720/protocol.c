#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* CARL SIDE */

    BIGNUM *p = BN_new(), *g = BN_new();

    BN_CTX *ctx  =BN_CTX_new();

    if(RAND_load_file("/dev/random", 64) != 64) handle_errors();

    if(!BN_generate_prime_ex(p, 64*8, 0, NULL, NULL, NULL)) handle_errors();
    
    BN_set_word(g, 5);

    //Bob random value b: it has to be max p-2, so I use 63 byte number
    BIGNUM *b = BN_new();

    BN_rand(b, 63*8, 0, 1);

    //Computing B = g^b mod p
    BIGNUM *B = BN_new();
    if(!BN_mod_exp(B, g, b, p, ctx)) handle_errors();

    //send_to_sara(p);
    //send_to_sara(g);
    //send_to_sara(B);

    /* SARA SIDE */
    BIGNUM *computed_carl = BN_new(); 
    //p = received_from_carl();
    //g = received_from_carl();
    //computed_carl = received_from_carl();

    BIGNUM *a = BN_new(), *A = BN_new();

    BN_rand(a, 63*8, 01, 1);

    //Computing A = g^a mod p
    BN_mod_exp(A, g, a, p, ctx);

    //Sending computed value to Carl
    //send_to_carl(A)

    //Computing the key
    BIGNUM *k = BN_new();

    BN_mod_exp(k, B, a, p, ctx);




    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(b);
    BN_free(B);
    BN_free(A);
    BN_free(k);
    BN_CTX_free(ctx);
}