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

    if(argc != 3) {
        fprintf(stderr, "Missing params. %s need two input files: 'filename1' 'filename2", argv[0]);
        abort();
    }
    
    FILE *input1 = fopen(argv[1], "rb"), *input2 = fopen(argv[2], "rb");
    
    if(input1 == NULL || input2 == NULL) {
        fprintf(stderr, "Error opening input files.\n");
        abort();
    }

    //Setting the context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());

    int md_len, nbytes_read;
    unsigned char buffer[MAXSIZE], md[EVP_MD_size(EVP_sha256())];

    //Reading input1.txt and computing digest
    while(nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input1)) {
        //Checking file reading
        if(ferror(input1)) {
            fprintf(stderr, "Error reading %s\n", argv[1]);
            abort();
        }
        
        //Computing signature
        if(!EVP_DigestUpdate(ctx, buffer, nbytes_read)) handle_errors();
    }

    //Reading input2.txt and computing digest
    while(nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input2)) {
        //Checking file reading
        if(ferror(input2)) {
            fprintf(stderr, "Error reading %s\n", argv[2]);
            abort();
        }
        
        //Computing signature
        if(!EVP_DigestUpdate(ctx, buffer, nbytes_read)) handle_errors();
    }

    //Computing final signature
    if(!EVP_DigestFinal(ctx, md, &md_len)) handle_errors();

    printf("(%s || %s) digest (len: %d):\n", argv[1], argv[2], md_len);
    for(int i = 0; i < md_len; i++) {
        printf("%2x", md[i]);
    }
    printf("\n");

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}
