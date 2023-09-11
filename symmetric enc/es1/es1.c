#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0
#define BYTE_SIZE 16
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    //Opening input file
    FILE *input = fopen(argv[1], "rb"), *output = fopen("output.txt", "rb+");
    
    //Checking input params
    if(argc != 3) {
        fprintf(stderr, "Missing or wrong params.\n%s needs an input 'filename' and an input 'encryption algorithm' (must be an OpenSSL-compliant string)\n", argv[0]);
        exit(1);
    }

    //Checking input and output files
    if(input == NULL || output == NULL) {
        fprintf(stderr, "Error opening file %s.\n", argv[1]);
        exit(1);
    }

    //Seeding the PRNG
    if(RAND_load_file("/dev/random", 32) != 32 ){
        fprintf(stderr, "Error seeding the PRNG.\n");
        exit(1);
    }    

    unsigned char key[BYTE_SIZE], iv[BYTE_SIZE], ciphertext[MAX_BUFFER+16], decrypted[MAX_BUFFER], buffer[MAX_BUFFER];
    int n_read_bytes, ciphertext_len=0;

    //Generating random key and iv
    RAND_priv_bytes(key, BYTE_SIZE);
    RAND_bytes(iv, BYTE_SIZE);

    printf("Key:    ", key);
    for(int i = 0 ; i < BYTE_SIZE; i++) {
        printf("%2x", key[i]);
    }
    printf("\n");

    printf("IV:     ", iv);
    for(int i = 0 ; i < BYTE_SIZE; i++) {
        printf("%2x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    //Setting the context. The cipher is passed to the ctx by means of EVP_get_cipherbyname("ciphername").
    //This function return an instance of const EVP_CIPHER basing on the input string 
    if(!EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[2]), key, iv, ENCRYPT)) handle_errors();

    //Reading input file
    while ((n_read_bytes = fread(buffer, sizeof(unsigned char), MAX_BUFFER, input)) > 0){
        if (ferror(input)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext, &ciphertext_len, buffer, n_read_bytes)) handle_errors();

        //Writing ciphertext in the output file
        if(fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, output) < ciphertext_len) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            abort();
        }
    }

    //Ciphering last data block
    if(!EVP_CipherFinal(ctx, ciphertext, &ciphertext_len)) handle_errors();

    //Writing last ciphertext block
    if(fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, output) < ciphertext_len) {
        fprintf(stderr, "Error writing last cipher block.\n");
        abort();
    };

    EVP_CIPHER_CTX_free(ctx);

    /* TO CHECK THE CORRECTNESS, UNCOMMENT THE CODE BELOW TO DECRYPT THE CIPHERTEXT FILE*/
    /*
    rewind(output);

    FILE *dec = fopen("dec.txt", "w");

    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    int decrypted_len = 0;

    if(!EVP_CipherInit(ctx1, EVP_get_cipherbyname(argv[2]), key, iv, DECRYPT)) handle_errors();

    while ((n_read_bytes = fread(buffer, sizeof(unsigned char), MAX_BUFFER, output)) > 0){
        if (ferror(output)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(!EVP_CipherUpdate(ctx, decrypted, &decrypted_len, buffer, n_read_bytes)) {
            handle_errors();
        }

        for(int i = 0; i < decrypted_len; i++) {
            printf("%c", decrypted[i]);
        }

        if (ferror(dec)){
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }
    }

    if(!EVP_CipherFinal(ctx1, decrypted, &decrypted_len));

    for(int i = 0; i < decrypted_len; i++){
        printf("%c", decrypted[i]);
    }

    EVP_CIPHER_CTX_free(ctx1);
    fclose(dec);
    */

    fclose(input);
    fclose(output);
    
    return 0;
}