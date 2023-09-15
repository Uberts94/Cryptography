#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#define SIZE 16

int main() {
    unsigned char random1[SIZE], random2[SIZE];

    //to seed the PRNG
    if(RAND_load_file("/dev/random", SIZE) != SIZE)
        fprintf(stderr, "Error with rand initialization.\n");

    RAND_bytes(random1, SIZE);
    RAND_bytes(random2, SIZE);
    

    printf("Random1:\n");
    for (int i = 0; i < SIZE/2; i++){   
        if(i == SIZE/2-1) printf("%02x", random1[i]);
        else printf("%02x-", random1[i]);
    }
    printf("\n");

    printf("Random2:\n");
    for (int i = 0; i < SIZE/2; i++){
        if(i == SIZE/2-1) printf("%02x", random2[i]);
        else printf("%02x-", random2[i]);
    }
    printf("\n");

    printf("Xoring random1 and random2:\n");
    for (int i = 0; i < SIZE/2; i++){
        random1[i]^=random2[i];
        if(i == SIZE/2-1) printf("%02x", random1[i]);
        else printf("%02x-", random1[i]);
    }
    printf("\n");

    printf("Test: xoring again random1 and random2, we should obtain the original random1. Let's try:\n");
    for (int i = 0; i < SIZE/2; i++){
        random1[i]^=random2[i];
        if(i == SIZE/2-1) printf("%02x", random1[i]);
        else printf("%02x-", random1[i]);
    }
    printf("\n");
    return 0;
}
