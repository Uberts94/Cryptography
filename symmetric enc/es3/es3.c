#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

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
        fprintf(stderr, "Missing params.\n%s need as input: 'input filename'\n");
        abort();
    }

    FILE *input = fopen(argv[1], "rb"), *output = fopen("output.txt", "rb+");

    if(input == NULL) {
        fprintf(stderr, "Error opening file %s.\n", argv[1]);
        abort();
    }

    //Seeding the PRNG
    if(RAND_load_file("/dev/random", 32) != 32 ){
        fprintf(stderr, "Error seeding the PRNG.\n");
        exit(1);
    } 

    unsigned char key[SIZE], iv[SIZE/2], ciphertext[MAXSIZE], buffer[MAXSIZE];
    int nbytes_read, lenght;

    //Generating the key
    RAND_priv_bytes(key, SIZE);

    printf("Generated key:\n");
    for(int i = 0; i <SIZE; i++)
        printf("%2x", key[i]); 
    printf("\n");

    //Generating the iv
    RAND_bytes(iv, SIZE/4);

    printf("Generated iv:\n");
    for(int i = 0; i <SIZE/4; i++)
        printf("%2x", iv[i]); 
    printf("\n");

    //Initilizing the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!EVP_EncryptInit(ctx, EVP_chacha20(), key, iv)) handle_errors();

    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0) {
        if(ferror(input)) {
            fprintf(stderr, "Error reading input file %s.\n", argv[1]);
            abort();
        }

        //Encryption
        if(!EVP_EncryptUpdate(ctx, ciphertext, &lenght, buffer, nbytes_read)) handle_errors();
        
        fwrite(ciphertext, sizeof(unsigned char), lenght, output);
               
        if(ferror(output)) {
            fprintf(stderr, "Error writing output file %s.\n");
            abort();
        }
    }
    
    //Last bytes
    if(!EVP_EncryptFinal(ctx, ciphertext, &lenght)) handle_errors();

    fwrite(ciphertext, sizeof(unsigned char), lenght, output);

    if(ferror(output)) {
            fprintf(stderr, "Error writing output file %s.\n");
            abort();
        }
    
    EVP_CIPHER_CTX_free(ctx);

    /* TO CHECK THE CORRECTNESS, UNCOMMENT THE CODE BELOW TO DECRYPT THE CIPHERTEXT FILE*/

    /*
    //Initilizing the context
    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    if(!EVP_DecryptInit(ctx1, EVP_chacha20(), key, iv)) handle_errors();
    unsigned char decrypted[MAXSIZE];

    rewind(output);

    EVP_DecryptInit(ctx1, EVP_chacha20(), key, iv);

    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, output)) > 0) {
        if(ferror(output)) {
            fprintf(stderr, "Error reading ciphertext file.\n");
            abort();
        }

        if(!EVP_DecryptUpdate(ctx1, decrypted, &lenght, buffer, nbytes_read)) handle_errors();
               
        for(int i = 0; i < lenght; i++)
            printf("%c", decrypted[i]);
    }

    if(!EVP_DecryptFinal(ctx1, decrypted, &lenght)) handle_errors();

    EVP_CIPHER_CTX_free(ctx1);
    */
    
    fclose(input);
    fclose(output);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}