#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    //Loading all the error strings
    ERR_load_crypto_strings();
    //Loading all the algorithms
    OpenSSL_add_all_algorithms();

    if(argc != 3) {
        fprintf(stderr, "Missing params. %s needs as input: 'filename' 'key'\n", argv[0]);
        abort();
    }

    FILE *input = fopen(argv[1], "rb");

    //Checking input file
    if(input == NULL) {
        fprintf(stderr, "Error opening input file.\n");
        abort();
    }

    //Initializing contexts and pkey
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, argv[2], 16);

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey)) handle_errors();
    

    unsigned char buffer[MAXSIZE], hmac_value[EVP_MD_size(EVP_sha256())];
    int nbytes_read;
    size_t hmac_len;

    //Reading file and computing hmac
    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0){
        if(ferror(input)){
            fprintf(stderr, "Error reading input file.\n");
            abort();
        }

        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, nbytes_read)) handle_errors();
    }

    //Computing final hmac
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len)) handle_errors();

    printf("\nFinal HMAC:\n");
    for(int i = 0; i < hmac_len; i++){
        printf("%02x", hmac_value[i]);
    }
    printf("\n");
    
    //Free contexts
    EVP_MD_CTX_free(hmac_ctx);

    //Closing file
    fclose(input);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}