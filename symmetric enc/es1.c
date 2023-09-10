#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0
#define BYTE_SIZE 16
#define HEX_SIZE 32

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    FILE *input = fopen(argv[1], "rb"), *output = fopen("output.txt", "rb+");
    int n_read_bytes, update_len, final_len, ciphertext_len=0;
    unsigned char buffer[10000];

    if(argc != 3) {
        fprintf(stderr, "Missing or wrong params.\n%s needs an input 'filename' and an input 'encryption algorithm' (must be an OpenSSL-compliant string)\n", argv[0]);
        exit(1);
    }

    if(input == NULL) {
        fprintf(stderr, "Error opening file %s.\n", argv[1]);
        exit(1);
    }

    if(RAND_load_file("/dev/random", 32) != 32 ){
        fprintf(stderr, "Error seeding the PRNG.\n");
        exit(1);
    }    

    unsigned char key[BYTE_SIZE], iv[BYTE_SIZE], plaintext[] = "this is the plaintext", ciphertext[1000], decrypted[1000];

    RAND_priv_bytes(key, BYTE_SIZE);
    RAND_bytes(iv, BYTE_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[2]), key, iv, ENCRYPT);

    while (1){
        n_read_bytes = fread(buffer, sizeof(unsigned char), 1000, input);
        if (ferror(input)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext, &update_len, buffer, strlen(buffer))) handle_errors();
        ciphertext_len+=update_len;

        fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, output);

        if (ferror(output)){
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(n_read_bytes < 1000) break;
    }

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &final_len)) handle_errors();
        ciphertext_len += final_len;

    fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, output);

    EVP_CIPHER_CTX_free(ctx);

    rewind(output);

    FILE *dec = fopen("dec.txt", "w");

    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    int decrypted_len = 0;

    EVP_CipherInit(ctx1, EVP_get_cipherbyname(argv[2]), key, iv, DECRYPT);

    while (1){
        n_read_bytes = fread(buffer, sizeof(unsigned char), 1000, output);
        if (ferror(output)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(!EVP_CipherUpdate(ctx, decrypted, &update_len, buffer, strlen(buffer))) {
            printf("\n\n1\n\n");
            handle_errors();
        }
        decrypted_len+=update_len;

        for(int i = 0; i < n_read_bytes; i++) {
            fprintf(dec, "%c", decrypted[i]);
        }

        if (ferror(dec)){
            printf("\n\n2\n\n");
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
        }

        if(n_read_bytes < 1000) break;
    }

    if(!EVP_CipherFinal(ctx1, decrypted+decrypted_len, &final_len));
    decrypted_len+=final_len;

    for(int i = 0; i < decrypted_len; i++){
        fprintf(dec, "%c", decrypted[i]);
    }

    EVP_CIPHER_CTX_free(ctx1);

    fclose(input);
    fclose(output);
    fclose(dec);
    return 0;
}