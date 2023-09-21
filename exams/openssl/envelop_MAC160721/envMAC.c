#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char* result){
    EVP_MD_CTX * ctx = EVP_MD_CTX_new();

    //Computing SHA256(SHA256(message||key))

    if(!EVP_DigestInit(ctx, EVP_sha256())) handle_errors();

    unsigned char keyed[] = strcat(message, key);
    unsigned char firstdgst[EVP_MD_size(EVP_sha256())];

    if(!EVP_DigestUpdate(ctx, keyed, strlen(keyed))) handle_errors();

    int dgst1_len;

    if(!EVP_DigestFinal(ctx, firstdgst, &dgst1_len)) handle_errors();

    if(!EVP_DigestInit(ctx, EVP_sha256())) handle_errors();

    if(!EVP_DigestUPdate(ctx, firstdgst, dgst1_len)) handle_errors();

    unsigned char finaldgst[EVP_MD_size(EVP_sha256())];

    int finaldgst_len;

    if(!EVP_DigestFinal(ctx, finaldgst, &finaldgst_len));

    EVP_MD_CTX_free(ctx);

    //Encryption with RSA key
    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);

    if(!EVP_PKEY_encrypt_init(rsa_ctx)) handle_errors();

    if(!EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING)) handle_errors();

    size_t encrypted_len = 0;

    if(!EVP_PKEY_encrypt(rsa_ctx, NULL, &encrypted_len, finaldgst, finaldgst_len)) handle_errors();

    unsigned char encrypted[encrypted_len];

    if(EVP_PKEY_encrypt(rsa_ctx, encrypted, &encrypted_len, finaldgst, finaldgst_len)) {
        result = encrypted;
        EVP_PKEY_CTX_free(rsa_ctx);
        return 1;
    }


    return 0;
}

