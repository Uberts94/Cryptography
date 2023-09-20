#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFF_SIZE 256

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int arg, char** argv) {
FILE* f_in;

unsigned char buff[BUFF_SIZE];
int i = 0;
unsigned char digest[EVP_MD_size(EVP_sha256())]; /*use the proper constant */
//SHA256_CTX context;

f_in = fopen(argv[1], "r");

if(f_in==NULL) handle_errors();


EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new();

if(!EVP_DigestInit(sha_ctx, EVP_sha256())) handle_errors();
int bytes_read = 0, d_len=0;

while((bytes_read = fread(buff, sizeof(unsigned char), BUFF_SIZE, f_in)) > 0) {
if(!EVP_DigestUpdate(sha_ctx, buff, bytes_read)) handle_errors();
}
if(!EVP_DigestFinal_ex(sha_ctx, digest, &d_len)) handle_errors();
for(int i = 0; i < d_len; i++)
    printf("%02x", digest[i]);
printf("\n");

EVP_MD_CTX_free(sha_ctx);
fclose(f_in);
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();

return 0;
}