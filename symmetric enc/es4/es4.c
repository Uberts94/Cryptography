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
    int lenght=0, update, final;

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
    int input_len = strlen(argv[1]), padding_lenght = SIZE-input_len%SIZE;
    if(input_len%SIZE != 0) {
        printf("The input size (%d bytes) isn't a multiple integer of the cipher block size (16 bytes for AES_128 bit).\n");
        unsigned char *padding, *padding_hex;

        //Dynamic memory allocation
        padding = malloc(padding_lenght * sizeof(unsigned char));
        padding_hex = malloc(padding_lenght * sizeof(unsigned char));
        ciphertext = malloc(input_len+padding_lenght * sizeof(unsigned char));

        //Generating random padding bytes. In this example, we generate padding_lenght/2 of bytes, 
        //because each byte is converted in a 2 digit hexadecimal byte (before the concatenation with the input)
        if(!RAND_bytes(padding, padding_lenght/2)) handle_errors();
        for(int i = 0; i < padding_lenght/2; i++) {
            //Converting each byte in a 2 digit hexadecimal byte
            sprintf(&padding_hex[i*2], "%02x", padding[i]);
        }
        printf("Generating padding ... ");
        for(int i = 0; i < padding_lenght; i++) printf("%c", padding_hex[i]);
        printf("\n");

        //Concatenating padding to input string
        strcpy(ciphertext, argv[1]);
        ciphertext = strcat(argv[1], padding_hex);
        printf("New input with padding: '%s'\n", ciphertext);
        printf("The new size (%d bytes) is a multiple integer of the cipher block size for AES_128 bit.\n", strlen(ciphertext));

        //Dynamic memory realease
        free(padding);
        free(padding_hex);
    }

    printf("Now we can encrypt the input....\n");
    //Encryption
    if(!EVP_EncryptUpdate(ctx, ciphertext, &update, argv[1], strlen(argv[1]))) handle_errors();
    lenght+=update;

    //Encryption of the last block
    if(!EVP_EncryptFinal(ctx, ciphertext+lenght, &final)) handle_errors();
    lenght+=final;

    printf("Ciphertext:\n");
    for(int i = 0; i < lenght; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    /* TO CHECK THE CORRECTNESS, UNCOMMENT THE CODE BELOW TO DECRYPT THE CIPHERTEXT FILE*/

    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx1, EVP_aes_128_cbc(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx1, 0);

    int decrypted_len = 0;
    unsigned char decrypted[MAXSIZE];

    EVP_DecryptUpdate(ctx, decrypted, &update, ciphertext, strlen(ciphertext));
    decrypted_len+=update;

    EVP_DecryptFinal(ctx, decrypted, &final);
    decrypted_len+=final;

    printf("Plaintext:\n");
    for(int i = 0; i < decrypted_len-padding_lenght; i++){
        printf("%c", decrypted[i]);
    }
    printf("\n");

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}