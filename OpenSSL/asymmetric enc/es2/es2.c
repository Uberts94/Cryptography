#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    size_t pri_len;// Length of private key
    size_t pub_len;// Length of public key

    if(argc != 3) {
        fprintf(stderr, "Missing params: %s needs in input 'public key filename' 'string to encrypt'", argv[0]);
        abort();
    }

    FILE *fpubkey = fopen(argv[1], "r");
    if(fpubkey == NULL) {
        fprintf(stderr, "Error reading public key file");
        abort();
    }

    // Setting public key from input file
    EVP_PKEY *publickey = PEM_read_PUBKEY(fpubkey, NULL, NULL, NULL);
    
    // The message to encrypt MUST be shorter than the RSA key length - padding
    if(strlen(argv[2]) >= EVP_PKEY_size(publickey)) handle_errors();


    // Create and initialize a new context for encryption.
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(publickey, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        handle_errors();
    }
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }

 
    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, argv[2], strlen(argv[2])) <= 0) {
        handle_errors();
    }


    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, argv[2], strlen(argv[2])) <= 0) {
        handle_errors();
    }


    // save the message to a file
    FILE *fout = fopen("out.bin", "w");
    if(fwrite(encrypted_msg, 1,  encrypted_msg_len, fout) < EVP_PKEY_size(publickey))
        handle_errors();
    fclose(fout);
    
    printf("Encrypted message written to file.\n");

    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_free(publickey);

/************************* UNCOMMENT THE SECTION BELOW TO DECRYPT*************************/
/*
    // NOTE: we are the receiver, we have the private key in memory, The private.pem file
    //      is in ./../private.pem path
    printf("Reading the encrypted message from file and attempting decryption...\n");
    FILE *fin = fopen("out.bin", "r"), *fprivatekey = fopen("./../private.pem", "r");

    if(fin == NULL) {
        fprintf(stderr, "Error opening encrypted file.\n");
        abort();
    }

    if(fprivatekey == NULL) {
        fprintf(stderr, "Error opening privatekey file.\n");
        abort();
    }

    // Setting private key from private.pem file
    EVP_PKEY *privatekey = PEM_read_PrivateKey(fprivatekey, NULL, NULL, NULL);
    
    // Checking size
    if (fread(encrypted_msg, 1, encrypted_msg_len, fin) != EVP_PKEY_size(privatekey))
        handle_errors();
    fclose(fin);

    // Setting the context
    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(privatekey, NULL);
    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        handle_errors();
    }

    // Setting padding
    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }

    size_t decrypted_msg_len;
    
    // Decrypting out.bin file
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_msg_len, encrypted_msg, encrypted_msg_len) <= 0) {
        handle_errors();
    }

    unsigned char decrypted_msg[decrypted_msg_len+1];

    if (EVP_PKEY_decrypt(dec_ctx, decrypted_msg, &decrypted_msg_len, encrypted_msg, encrypted_msg_len) <= 0) {
        handle_errors();
    }

    decrypted_msg[decrypted_msg_len] = '\0';
    printf("Decrypted Plaintext is:\n-->%s\n",decrypted_msg);
    // BIO_dump_fp(stdout, (const char*) decrypted_msg, decrypted_msg_len);

    EVP_PKEY_CTX_free(dec_ctx);
    EVP_PKEY_free(privatekey);
*/
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();


    return 0;
}
