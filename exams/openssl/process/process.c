#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

char *process(char * data, int lenght, RSA *rsa_priv_key) {
    // Checks if data can be decrypted by means RSA private key 
    // obatins decrypted_data by means manually RSA decryption
    // computes the SHA256 hash of decrypted data
    // If data can be decrypted, return 3 bytes:
    // - the least significant bit of decrypted data
    // - the least significant bit of hash(decrypted data)
    // - the XOR of the previous 2 bytes

    if(strlen(data) > RSA_size(rsa_priv_key)) return NULL;

    // RSA decryption consists in : P = C^d mod p
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p, *d, *ctext = BN_new();
    p = rsa_priv_key->p;
    d = rsa_priv_key->d;

    BN_set_word(ctext, data);

    BIGNUM *dec = BN_new();
    
    if(!BN_mod_exp(dec, ctext, d, p, ctx)) handle_errors();

    unsigned char *decrypted_data = BN_bn2hex(dec);
    
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(d);
    BN_free(ctext);

    EVP_MD_CTX *ctx_dgst = EVP_MD_CTX_new();

    if(!EVP_DigestInit(ctx_dgst, EVP_sha256())) handle_errors();

    if(!EVP_DigestUpdate(ctx_dgst, decrypted_data, strlen(decrypted_data))) handle_errors();

    unsigned char dgst[EVP_MD_size(EVP_sha256())];
    int len = 0;

    if(!EVP_DigestFinal_ex(ctx_dgst, dgst, &len)) handle_errors();

    EVP_MD_CTX_free(ctx_dgst);

    char res[3];

    res[0] = decrypted_data[strlen(decrypted_data)-1];
    res[1] = dgst[len-1];
    res[2] = res[0] ^ res[1];

    return res;
}

int main(){

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */ 
    OpenSSL_add_all_algorithms();

    //call to process();

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}