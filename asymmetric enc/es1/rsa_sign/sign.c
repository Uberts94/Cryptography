#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


#define KEY_LENGTH  2048
#define MAXBUFFER 1024



void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s file_to_sign file_private_key\n",argv[0]);
        exit(1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }
    FILE *f_key;
    if((f_key = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(f_key,NULL,NULL,NULL);

    EVP_MD_CTX  *sign_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
            handle_errors();
    
    size_t n_read;
    unsigned char buffer[MAXBUFFER];
    while((n_read = fread(buffer,1,MAXBUFFER,f_in)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }

    
    size_t sig_len;
        if(!EVP_DigestSignFinal(sign_ctx, NULL, &sig_len))
        handle_errors();

    unsigned char signature[sig_len];

    // size_t sig_len = digest_len;
    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);
    
    // save the signature to a file
    FILE *out = fopen("sig.bin", "w");
    if(fwrite(signature, 1,  sig_len, out) < sig_len)
        handle_errors();
    fclose(out);
    printf("Signature written to the output file.\n");

    EVP_PKEY_free(private_key);
    
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();

    return 0;
}