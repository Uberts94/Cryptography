#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define SIZE 16
#define ENCRYPT 1
#define DECRYPT 0
#define MAX_SIZE 1024

//error handling
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char key[SIZE], IV[SIZE], data[] = "This is the plaintext to encrypt. One it's encrypted, I'll try to decrypt", ciphertext[MAX_SIZE];

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    //to seed the PRNG
    if(RAND_load_file("/dev/random", SIZE) != SIZE)
        fprintf(stderr, "Error with rand initialization.\n");

    RAND_priv_bytes(key, SIZE);
    RAND_priv_bytes(IV, SIZE);

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, ENCRYPT);

    int update_len, final_len;
    int ciphertext_len=0;

    EVP_CipherUpdate(ctx,ciphertext,&update_len,data,strlen(data));
    ciphertext_len+=update_len;
    printf("update size: %d\n",ciphertext_len);

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
