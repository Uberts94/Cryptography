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
    unsigned char key[SIZE], IV[SIZE], data[] = "This is the plaintext to encrypt. Once it's encrypted, I'll try to decrypt", ciphertext[MAX_SIZE], ciphertext_hex[MAX_SIZE];

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    FILE* output = fopen("./output.txt", "r+");

    if (output == NULL){
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }

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

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;
    printf("Data to be encrypted:   %s\n", data);
    printf("Ciphertext lenght = %d\nCiphertext:     ", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++) {
        //Storing ciphertext in output.txt
        //I use a file to store the ciphertext, the one that I'll decrypt later to test this part (the encryption part)
        fprintf(output, "%02x", ciphertext[i]);
    }

    rewind(output);
    while (fscanf(output, "%s", ciphertext_hex)!=EOF){
        printf("%s", ciphertext_hex);
    }
    printf("\n\n");

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, DECRYPT);

    ciphertext_len=strlen(ciphertext_hex)/2;
    unsigned char ciphertext_binary[ciphertext_len];

    //Converting ciphertext from exadecimal to binary
    for(int i = 0; i < ciphertext_len;i++){
        sscanf(&ciphertext_hex[2*i],"%2hhx", &ciphertext_binary[i]);
    }


    unsigned char decrypted[ciphertext_len];
    int decrypted_len=0;
    EVP_CipherUpdate(ctx, decrypted, &update_len, ciphertext_binary, ciphertext_len);
    decrypted_len+=update_len;

    EVP_CipherFinal(ctx, decrypted+decrypted_len, &final_len);
    decrypted_len+=final_len;

    printf("Deciphering ciphertext...\n");
    for(int i = 0; i < decrypted_len; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\nEverything ok!");


    EVP_CIPHER_CTX_free(ctx);

    fclose(output);

    return 0;
}
