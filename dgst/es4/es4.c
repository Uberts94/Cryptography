#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define SIZE 32
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

    if(argc != 2) {
        fprintf(stderr, "Missing params. %s needs as input: 'filename'\n", argv[0]);
        abort();
    }

    FILE *input = fopen(argv[1], "rb");
    unsigned char buffer[MAXSIZE], md256[EVP_MD_size(EVP_sha256())], md512[EVP_MD_size(EVP_sha512())];
    int nbytes_read, md256len, md512len;

    if(input == NULL) {
        fprintf(stderr, "Error opening input file.\n");
        abort();
    }

    //Initializing contexts
    EVP_MD_CTX *ctx256 = EVP_MD_CTX_new(), *ctx512 = EVP_MD_CTX_new();
    if(!EVP_DigestInit(ctx256, EVP_sha256())) handle_errors();
    if(!EVP_DigestInit(ctx512, EVP_sha512())) handle_errors();

    //Reading file and computing digests
    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0){
        if(ferror(input)){
            fprintf(stderr, "Error reading input file.\n");
            abort();
        }

        if(!EVP_DigestUpdate(ctx256, buffer, nbytes_read)) handle_errors();
        if(!EVP_DigestUpdate(ctx512, buffer, nbytes_read)) handle_errors();
    }

    //Computing final digests
    if(!EVP_DigestFinal(ctx256, md256, &md256len)) handle_errors();
    if(!EVP_DigestFinal(ctx512, md512, &md512len)) handle_errors();

    printf("\nFinal digest:\n");
    for(int i = 0; i < md256len; i++){
        printf("%02x", md256[i]^(md512[i]&md512[i+256]));
    }
    printf("\n");
    
    //Free contexts
    EVP_MD_CTX_free(ctx256);
    EVP_MD_CTX_free(ctx512);

    //Closing file
    fclose(input);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}