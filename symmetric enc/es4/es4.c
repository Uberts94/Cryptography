#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

#define SIZE 16
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
        fprintf(stderr, "Missing params. %s need an input string to be encrypted be means AES_128_cbc.\n", argv[0]);
        abort();
    }

    //Seeding PRNG
    if(RAND_load_file("/dev/random", 32) != 32) handle_errors();

    unsigned char key[SIZE], iv[SIZE], *ciphertext;
    int lenght=0, update;

    //Keygen
    if(!RAND_priv_bytes(key, SIZE)) handle_errors();

    printf("Generated key:");
    for(int i = 0; i < SIZE; i++)
        printf("%2x", key[i]);
    printf("\n");

    //IV gen
    if(!RAND_bytes(iv, SIZE)) handle_errors();

    printf("Generated iv:");
    for(int i = 0; i < SIZE; i++)
        printf("%2x", iv[i]);
    printf("\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    //Disabling padding
    if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) handle_errors();

    //Checking the input len
    int input_len = strlen(argv[1]);
    if(input_len%SIZE != 0) {
        printf("We need padding, because the input size ins't an integer multiple of the cipher block size (AES_128 bit)\n");
        unsigned char *padding, *padding_hex;
        padding = malloc(input_len%16 * sizeof(unsigned char));
        padding_hex = malloc(input_len%16*2 * sizeof(unsigned char));
        ciphertext = malloc(input_len * sizeof(unsigned char));
        if(!RAND_bytes(padding, 16-input_len%16)) handle_errors();
        for(int i = 0; i < 16-input_len%16; i++) {
            sscanf(&padding[i], "%2x", &padding_hex[i*2]);
            printf("%c", padding[i*2]);
        }
        ciphertext = strcat(argv[1], padding_hex);
        printf("New input: '%s'\n", ciphertext);
        printf("New input size: %d\n", strlen(strcat(argv[1], padding)));
        free(padding);
        free(padding_hex);
    }

    //Encryption
    if(!EVP_EncryptUpdate(ctx, ciphertext, &update, argv[1], strlen(argv[1]))) handle_errors();
    lenght+=update;

    if(!EVP_EncryptFinal(ctx, ciphertext+lenght, &lenght)) handle_errors();

    printf("Ciphertext:\n");
    for(int i = 0; i < lenght; i++) {
        printf("%2x", ciphertext[i]);
    }
    printf("\n");
/*
    //Last block encryption
    if(!EVP_EncryptFinal(ctx, ciphertext, &update)) {
        printf("Padding needed!");
        int input_len = strlen(argv[1]);
        printf("Input string len: %d\n", input_len);
        printf("AES128 bit need %d padding bytes for the last block....", input_len%16);
        printf("Generated padding: ");
        unsigned char *padding;
        padding = malloc(input_len%16 * sizeof(unsigned char));
        if(!RAND_bytes(padding, 10)) handle_errors();
        printf("%s\n", padding);
        ciphertext = strcat(ciphertext+(input_len/16))
        if(!EVP_EncryptFinal_ex(ctx, last_block+lenght, &lenght)) handle_errors();
        free(padding);
    } else {
        lenght+=update;
        for(int i = 0; i < lenght; i++) {
            printf("%2x", ciphertext[i]);
        }
    }
*/

    EVP_CIPHER_CTX_free(ctx);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}