#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/rand.h>

#define SIZE 4

int main() {
    unsigned char random1[SIZE];

    if (RAND_load_file("/dev/random", SIZE)!= SIZE){
        fprintf(stderr, "Error initializing the PRNG.\n");
    }
    RAND_bytes(random1, SIZE);
    
    for(int i = 0 ; i < SIZE; i++) {
        printf("%2x", random1[i]);
    }
    
    uint32_t number1 = *(uint32_t*)random1;
    printf("\nCasting 4 bytes into integer: %"PRIu32"\n", number1);

    return 0;
}