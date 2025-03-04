#ifndef __HW2_H
#define __HW2_H

#define INFO(...) do {fprintf(stderr, "[          ] [ INFO ] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr);} while(0)
#define ERROR(...) do {fprintf(stderr, "[          ] [ ERR  ] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr);} while(0) 

#define EXPANDED_KEYS_LENGTH 32

#include <stdint.h>

void print_packet(unsigned char packet[]);

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number);

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths);



// PART IV

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys);

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys);

void sbu_decrypt(block_t *encrypted_input, uint8_t *plaintext_output, size_t pt_len, uint32_t *expanded_keys);

#endif // HW2_H
