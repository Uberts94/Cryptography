#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

    //Checking params
    if(argc != 2) {
        fprintf(stderr, "Missing params. %s need the input 'filename'\n", argv[0]);
        abort();
    }

    FILE *input = fopen(argv[1], "rb");
    int nbytes_read, md_len;
    unsigned char buffer[MAXSIZE], md[EVP_MD_size(EVP_sha256())];

    //Checking file
    if(input == NULL) {
        fprintf(stderr,"Error opening %s file.\n", argv[1]);
        abort();
    } 

    //Setting context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_DigestInit(md_ctx, EVP_sha256());

    //Reading file and computing incremental digest
    while(nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input) > 0) {
        if(ferror(input)) {
            fprintf(stderr, "Error reading %s file.\n", argv[0]);
            abort();
        }
        if(!EVP_DigestUpdate(md_ctx, buffer, nbytes_read)) handle_errors();
    }

    //Computing final digest
    if(!EVP_DigestFinal(md_ctx, md, &md_len)) handle_errors();

    printf("Digest:\n");
    for(int i = 0; i < md_len; i++){
        printf("%2x", md[i]);
    }

    //Free context
    EVP_MD_CTX_free(md_ctx);

    //Closing file
    fclose(input);


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}