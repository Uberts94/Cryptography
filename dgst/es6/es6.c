#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

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

    if(argc != 3) {
        fprintf(stderr, "Missing params. %s needs as input: 'hmac' 'filename'\n", argv[0]);
        abort();
    }
        
    FILE *input = fopen(argv[2], "rb");

    //Checking input file
    if(input == NULL) {
        fprintf(stderr, "Error opening input file.\n");
        abort();
    }

    //Initializing contexts and pkey
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    unsigned char key[] = "56e4fd53235681ea3ccc91f4f15d6d47c60520a3fe4d80c0bcd72d4ccb52932c";
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 16);

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey)) handle_errors();
    

    unsigned char buffer[MAXSIZE], hmac_value[EVP_MD_size(EVP_sha256())];
    int nbytes_read;
    size_t hmac_len;

    //Reading file and computing hmac
    while((nbytes_read = fread(buffer, sizeof(unsigned char), MAXSIZE, input)) > 0){
        if(ferror(input)){
            fprintf(stderr, "Error reading input file.\n");
            abort();
        }

        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, nbytes_read)) handle_errors();
    }

    //Computing final hmac
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len)) handle_errors();

    printf("\nFinal HMAC:\n");
    for(int i = 0; i < hmac_len; i++){
        printf("%02x", hmac_value[i]);
    }
    printf("\n");
    
    printf("Received HMAC:\n%s\n", argv[1]);

    unsigned char hmac_binary[strlen(argv[1])/2];
    for(int i = 0; i < strlen(argv[1])/2;i++){
        sscanf(&argv[1][2*i],"%2hhx", &hmac_binary[i]);
    }

    // if( CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0 )
    if( (hmac_len == (strlen(argv[1])/2)) && (CRYPTO_memcmp(hmac_value, hmac_binary, hmac_len) == 0) )
        printf("Verification successful\n");
    else
        printf("CRYPTO_memcpm returns %d. Verification failed\n", CRYPTO_memcmp(hmac_value, hmac_binary, hmac_len/2));


    //Free contexts
    EVP_MD_CTX_free(hmac_ctx);

    //Closing file
    fclose(input);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
    return 0;
}