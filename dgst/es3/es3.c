#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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

    FILE *input = fopen(argv[1], "rb");

    //Checking params
    if(argc != 3) {
        fprintf(stderr, "Missing or wrong params. %s needs 2 input params: 'filename' 'sign algorithm' (in OpenSSL style algo names)", argv[0]);
        abort();
    }

    //Checking file
    if(input == NULL) {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
        abort();
    }

    //Checking input algorithm
    EVP_MD *algo = EVP_MD_fetch(NULL, argv[2], NULL);
    if((algo == NULL)) handle_errors();

    int md_len, nbytes_read;
    unsigned char buffer[MAXSIZE], md[EVP_MD_size(algo)]; 

    //Initializing context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, algo);

    //Reading file and computing incremental digest
    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0) {
        if(ferror(input)) {
            fprintf(stderr, "Error reading input file\n");
            abort();
        }

        //Computing incremental digest
        if(!EVP_DigestUpdate(ctx, buffer, nbytes_read)) handle_errors();
    }

    //Final digest computation
    if(!EVP_DigestFinal(ctx, md, &md_len)) handle_errors();

    printf("'%s' digest of the input file '%s':\n", argv[2], argv[1]);
    for(int i = 0; i < md_len; i++) {
        printf("%2x", md[i]);
    }
    printf("\n");

    //Free context
    EVP_MD_CTX_free(ctx);
    //Free fetched algorithm
    EVP_MD_free(algo);
    
    //Closing file
    fclose(input);
    
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}