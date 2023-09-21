#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define BITS 256

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    if(RAND_load_file("/dev/random", 64) != 64) handle_errors();

    unsigned char r1[BITS/8], r2[BITS/8];

    RAND_bytes(r1, BITS/8);
    RAND_bytes(r2, BITS/8);
    
    unsigned char key_simm[BITS/8];

    for(int i = 0; i < BITS/8; i++)
        key_simm[i] = r1[i] ^ r2[i];

    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;

    if(!(rsa_keypair = EVP_RSA_gen(bits))) handle_errors();

    FILE *rsa_pubkey = fopen("public.pem", "w");

    if(!PEM_write_PUBKEY(rsa_pubkey, rsa_keypair)) handle_errors();

    fclose(rsa_pubkey);

    FILE *rsa_privkey = fopen("private.pem", "w");

    if(!PEM_write_PrivateKey(rsa_privkey, rsa_keypair, EVP_aes_256_cbc(), key_simm, BITS/8, NULL, NULL))
        handle_errors();

    EVP_PKEY_free(rsa_keypair);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
}