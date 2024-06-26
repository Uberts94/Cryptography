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

    //Checking params
    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s signature_to_verify file_public_key\n",argv[0]);
        exit(1);
    }
    
    //Opening public.pem file
    FILE *f_pubkey;
    if((f_pubkey = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }  

    //setting the received public key
    EVP_PKEY* public_key = PEM_read_PUBKEY(f_pubkey,NULL,NULL,NULL);
    fclose(f_pubkey);

    //opening signature file
    FILE *fsig_in = fopen(argv[1], "rb");
    if(fsig_in == NULL) {
        fprintf(stderr, "Error opening the signature file.\n");
        abort();
    }

    printf("Reading the signature from file and attempting verification...\n");
    unsigned char signature_from_file [MAXBUFFER]; // we don't know in advance the size of the signature
    
    //Computing signature lenght
    size_t sig_len_from_file;
    if ((sig_len_from_file = fread(signature_from_file, 1, MAXBUFFER, fsig_in)) != EVP_PKEY_size(public_key))
        handle_errors();
    
    EVP_MD_CTX  *verify_ctx = EVP_MD_CTX_new();

    //Setting verify context
    if(!EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, public_key)) handle_errors();

    size_t n_read;
    unsigned char buffer[MAXBUFFER];
    rewind(fsig_in);
    //Reading again signature file
    while((n_read = fread(buffer,1,MAXBUFFER,fsig_in)) > 0){
        if(!EVP_DigestVerifyUpdate(verify_ctx, buffer, n_read))
            handle_errors();
        
    }
    
    //Verifying signature
    if(EVP_DigestVerifyFinal(verify_ctx, signature_from_file, sig_len_from_file)) printf("Verification successful\n");
    else printf("Verification failed\n");
    
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(public_key);
    fclose(fsig_in);
     
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();

    return 0;
}