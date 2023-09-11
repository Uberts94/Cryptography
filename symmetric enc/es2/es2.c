#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXSIZE 1024

#define ENCRYPT 1
#define DECRYPT 0

/*
    NOTES:
        for this execise, I used (as input) the output file of the es1. So the params of this program are:
        1)'path of es1 output file' 
        2)'key, printed on the stdout by es1'
        3)'iv, printed on the stdout by es1' 
        4)'path of the output file (must be created before the run)'
*/

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    //Loading all the error strings
    ERR_load_crypto_strings();
    //Loading all the algorithms
    OpenSSL_add_all_algorithms();

    //Checking input params
    if(argc != 5) {
        fprintf(stderr, "Missing or wrong parms.\n%s has the following params in input: 'file_to_decipher' 'key' 'iv' 'output_file");
        return(1);
    }

    FILE *input = fopen(argv[1], "rb"), *output = fopen(argv[4], "rb+");

    //Checking input and output files
    if(input == NULL || output == NULL){
        fprintf(stderr, "Error opening files.\n");
        return(1);
    }

    unsigned char buffer[MAXSIZE], decrypted[MAXSIZE];
    int decrypted_len = 0, nbytes_read;

    //Acquiring binary key from the hex representation
    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &key[i]);
    }

    //Acquiring binary iv from the hex representation
    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2;i++){
        sscanf(&argv[3][2*i],"%2hhx", &iv[i]);
    }

    //Creating and initializing the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT)) handle_errors();

    //Reading input file (the one to be deciphered)
    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0){
        if(ferror(input)) {
            fprintf(stderr, "Error reading input file.\n");
            abort();
        }

        //Deciphering
        if(!EVP_CipherUpdate(ctx, decrypted, &decrypted_len, buffer, nbytes_read)) handle_errors();

        for(int i = 0; i < decrypted_len; i++)
            fprintf(output, "%c", decrypted[i]);

        if(ferror(output)){
            fprintf(stderr, "Error writing output.\n");
            abort();
        }
    }

    //Deciphering the last block
    if(!EVP_CipherFinal(ctx, decrypted, &decrypted_len)) handle_errors();

    //Printing in the output file
    for(int i = 0; i < decrypted_len; i++)
        fprintf(output, "%c", decrypted);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input);
    fclose(output);

    return 0;
}