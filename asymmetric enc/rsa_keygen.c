#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>    
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}



int main(){
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();


    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;
    ;
    if((rsa_keypair = EVP_RSA_gen(bits)) == NULL ) 
        handle_errors();

    // 2. save public key
    FILE *rsa_public_file = NULL;
    if((rsa_public_file = fopen("public.pem","w")) == NULL) {
            fprintf(stderr,"Couldn't create the private key file.\n");
            abort();
    }
    if(!PEM_write_PUBKEY(rsa_public_file, rsa_keypair))
        handle_errors();
    fclose(rsa_public_file);

    // 3. save private key (without encrypting it on disk)
    FILE *rsa_private_file = NULL;
    if((rsa_private_file = fopen("private.pem","w")) == NULL) {
            fprintf(stderr,"Couldn't create the private key file.\n");
            abort();
    }
    if(!PEM_write_PrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(rsa_public_file);

    // 4. free
    EVP_PKEY_free(rsa_keypair);
    
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();


    return 0;
}
