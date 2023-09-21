#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#define ENC 1
#define DEC 0

#define FILESIZE 1000000
#define MAXSIZE 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    RSA *bob_pubkey;

    FILE *file_in = fopen("input.txt", "rb");

    if(file_in == NULL) {
        fprintf(stderr, "Error opening file.\n");
        abort();
    }

    if(RAND_load_file("/dev/random", 64) != 64) handle_errors();

    unsigned char key[32], iv[32];

    RAND_bytes(iv, 32);
    RAND_bytes(key, 32);

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPER_CTX_new();

    if(!EVP_CipherInit(aes_ctx, EVP_aes_256_cbc(), key, iv, ENC)) handle_errors();

    unsigned char ciphertext[FILESIZE];
    int update_len, final_len, ciphertext_len = 0, nbytes_read;
    unsigned char buffer[MAXSIZE];

    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, file_in)) > 0) {
        if(ciphertext_len > FILESIZE - nbytes_read - EVP_CIPHER_CTX_block_size(aes_ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+
            fprintf(stderr,"The file to cipher is larger than I can\n");
            abort();
        }

        if(!EVP_CipherUpdate(aes_ctx,ciphertext+ciphertext_len,&update_len,buffer,nbytes_read))
            handle_errors();
        ciphertext_len+=update_len;
    }
    
    if(!EVP_CipherFinal_ex(aes_ctx,ciphertext+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(aes_ctx);

    int encrypted_key_len = 0;
    unsigned char encrypted_key[RSA_size(bob_pubkey)];

    if((encrypted_key_len = RSA_public_encrypt(strlen(key)+1, key, encrypted_key, bob_pubkey, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();

    // send_bob(ciphertext);
    // senb_bob(encrypted_key);
    // send_bob(iv);

    free(bob_pubkey);
    fclose(file_in);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();
}

