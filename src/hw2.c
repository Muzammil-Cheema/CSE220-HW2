#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>

/*
Understanding the Aflent Protocol
Array Number isn't useful
Frag tells us which packet number we are at
max_frag_size is how many payload bytes each packet can store
Length or data_length is how many data values we need to hold in total
*/

//Packet Code:

//Increments a packet pointer. Assumes the pointer currently points at the first byte of a valid packet. 
unsigned char* increment_pointer(unsigned char *pointer){
	pointer += 3 + (4 * (((pointer[1] & 0x1F) << 5) | ((pointer[2] & 0xF8) >> 3)));
	return pointer;
}

void print_packet(unsigned char packet[])
{
	unsigned char array_number = packet[0] >> 2;
    unsigned char fragment_number = ((packet[0] & 0x03) << 3) | ((packet[1] & 0xE0) >> 5);
    unsigned short length = ((packet[1] & 0x1F) << 5) | ((packet[2] & 0xF8) >> 3);
    unsigned char encrypted = (packet[2] & 0x04) >> 2;
    unsigned char endianness = (packet[2] & 0x02) >> 1;
    unsigned char last = packet[2] & 0x01;

	printf("Array Number: %hhu\n", array_number);
	printf("Fragment Number: %hhu\n", fragment_number);
	printf("Length: %hu\n", length);
	printf("Encrypted: %hhu\n", encrypted);
	printf("Endianness: %hhu\n", endianness);
	printf("Last: %hhu\n", last);
	printf("Data: ");

	unsigned char *dataPtr = &packet[3];

	for (int i = 0; i < length; i++){
		unsigned int value;

		if (endianness){
			value = (
				(*dataPtr)		|
				(*(dataPtr+1) << 8)	| 
				(*(dataPtr+2) << 16)	|
				(*(dataPtr+3) << 24)
			);
			dataPtr+=4;
		} else {
			value = (
				(*(dataPtr) << 24)	|
				(*(dataPtr+1) << 16)	| 
				(*(dataPtr+2) << 8)	|
				(*(dataPtr+3))
			);
			dataPtr+=4;
		}

		printf("%x ", value);
	}

	dataPtr = NULL;
}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number)
{
	int total_fragments = (int) ceil(data_length * 4.0 / max_fragment_size);	//Number of packets needed
	unsigned char *original_packet_ptr = (unsigned char*) calloc(total_fragments, 3 + max_fragment_size);	//Packet array pointer that will be returned (pointer unchanged in this function)
	unsigned char *packet_ptr = original_packet_ptr;

	int data_index = 0;	//Index of the current data value we are reading.
	//For each packet...
	for (int fragment_number = 0; fragment_number < total_fragments; fragment_number++, packet_ptr+=(3+max_fragment_size)){
		unsigned short length = 0; //Equals the number of 32-bit values in a given payload. Stored in the header. 

		//Stores data according to endianness. Values are stored until the number of values stored by the current packet reaches max_fragment_size or until there are no values left to store in the data int array. 
		if (endianness){
			for (int payload_location = 3; payload_location < max_fragment_size + 3 && data_index < data_length; payload_location+=4, data_index++, length++){
				packet_ptr[payload_location] = data[data_index] & 0x000000FF;
				packet_ptr[payload_location+1] = (data[data_index] & 0x0000FF00) >> 8;
				packet_ptr[payload_location+2] = (data[data_index] & 0x00FF0000) >> 16;
				packet_ptr[payload_location+3] = (data[data_index] & 0xFF000000) >> 24;
			}
		} else {
			for (int payload_location = 3; payload_location < max_fragment_size + 3 && data_index < data_length; payload_location+=4, data_index++, length++){
				packet_ptr[payload_location+3] = data[data_index] & 0x000000FF;
				packet_ptr[payload_location+2] = (data[data_index] & 0x0000FF00) >> 8;
				packet_ptr[payload_location+1] = (data[data_index] & 0x00FF0000) >> 16;
				packet_ptr[payload_location] = (data[data_index] & 0xFF000000) >> 24;
			}
		}

		//Sets the three header bytes for each packet
		packet_ptr[0] = ((array_number & 0x3F) << 2) | ((fragment_number >> 3) & 0x3);
		packet_ptr[1] = ((fragment_number & 0x7) << 5) | ((length >> 5) & 0x1F);
		packet_ptr[2] = ((length & 0x1F) << 3) | 0 << 2 | endianness << 1 | (total_fragments == (fragment_number+1) ? 1 : 0);
	}

	//Nullify obsolete pointers
	packet_ptr = NULL;
	return original_packet_ptr;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths)
{
	int **return_array = (int**) calloc(array_count, sizeof(int*));	//Allocates array of int pointers
	int **fragment_offsets = (int**) calloc(array_count, sizeof(int*));	//Tracks which index we start writing to in return_array[i][j]for a given fragment (j) in a given array (i). 


	for (int i = 0; i < array_count; i++)	//Ensures array_lengths starts with all 0s. 
		array_lengths[i] = 0;

	int total_fragments = 0;	//The total number of packets in the packets[] array.
	int lastCounter = 0;	//Counts how many last fragments are found. Used to find total_fragments
	unsigned char* packet_ptr = packets;



	while (lastCounter < array_count){	//Loop until we have found all the last fragments
		if ((packet_ptr[2] & 1)){	//If packet is last 
			total_fragments += (((packet_ptr[0] & 0x03) << 3) | ((packet_ptr[1] & 0xE0) >> 5)) + 1;	//Add fragment number plus one (0-indexed correction) to the total_fragments count. The calculated value is the number of fragments for this array. 
			lastCounter++;
		}
		packet_ptr = increment_pointer(packet_ptr);	//Increments packet_ptr by the size of the current packet.
	}

	//Find the length of each array by obtaining the length value from each packet. In the loop, we need the array_number to know which array the current fragment belongs to.
	packet_ptr = packets;
	for (int i = 0; i < total_fragments; i++){
		array_lengths[packet_ptr[0] >> 2] += ((packet_ptr[1] & 0x1F) << 5) | ((packet_ptr[2] & 0xF8) >> 3);	//Increases array_lengths[array_number] by the length value of the current packet. 
		packet_ptr = increment_pointer(packet_ptr);
	}

	//Allocates exactly enough bytes to store each data value correctly in return_array and enough bytes to store the fragment offsets. 
	for (int i = 0; i < array_count; i++){
		return_array[i] = (int*) calloc(array_lengths[i], sizeof(int));
		fragment_offsets[i] = (int*) calloc(array_lengths[i] - 1, sizeof(int));
	}

	//Determine the index that a given fragment of a given array should start writing to. The data from a fragment j of array i will start writing to the fragment_offsets[i][j-1]^th index of return_array[i].
	packet_ptr = packets;
	for (int i = 0; i < total_fragments; i++){
		int array_num = packet_ptr[0] >> 2;
		int frag_num = ((packet_ptr[0] & 0x03) << 3) | ((packet_ptr[1] & 0xE0) >> 5);
		int length = (((packet_ptr[1] & 0x1F) << 5) | ((packet_ptr[2] & 0xF8) >> 3));
		int last = (packet_ptr[2] & 1);

		if (!last){
			for (int j = frag_num; j < array_lengths[array_num]; j++){
				fragment_offsets[array_num][j] += length;
			}
		}
		
		packet_ptr = increment_pointer(packet_ptr);
	}




	packet_ptr = packets;
	//For each packet...
	for (int packet = 0; packet < total_fragments; packet++){
		int array_num = packet_ptr[0] >> 2;
		int frag_num = ((packet_ptr[0] & 0x03) << 3) | ((packet_ptr[1] & 0xE0) >> 5);
		int length = ((packet_ptr[1] & 0x1F) << 5) | ((packet_ptr[2] & 0xF8) >> 3);
		int endian = (packet_ptr[2] & 0x02) >> 1;
		//For each data value in this packet...
		for(int data_index = 0; data_index < length; data_index++){
			//Set return_array at [array_number of packet][array index to start at] to data_index^th data value from this packet based on the endianness of this packet. If frag_num == 0, then we start at return_array[array_num][0], else we start writing data at an offset determined by fragment_offsets. As data_index increments, the return_array's jth index increments. 
			return_array[array_num][data_index + ((frag_num) ? fragment_offsets[array_num][frag_num-1] : 0)] 
				= (endian) 
				? 	
					(packet_ptr[(4*data_index)+6]) << 24	| 
					(packet_ptr[(4*data_index)+5]) << 16	|
					(packet_ptr[(4*data_index)+4]) << 8		|
					(packet_ptr[(4*data_index)+3])	
				:
					(packet_ptr[(4*data_index)+3]) << 24	| 
					(packet_ptr[(4*data_index)+4]) << 16	|
					(packet_ptr[(4*data_index)+5]) << 8		|
					(packet_ptr[(4*data_index)+6]) 
			;
		}

		packet_ptr = increment_pointer(packet_ptr);
	}

	packet_ptr = NULL;
    return return_array;
}


//Encryption Code:

#define EXPANDED_KEYS_LENGTH 32

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t(*permute_func_t)(block_t);

block_t table[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};

// ----------------- Bitwise Functions ----------------- //

uint8_t rotl(uint8_t x, uint8_t shamt)
{
    return (x << (shamt%8)) | (x >> (8 - (shamt%8)));
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
    return (x >> (shamt%8)) | (x << (8 - (shamt%8)));
}

block_t reverse(block_t x)
{
	block_t reverse = 0;
	for (int i = 0; i < 32; i++){
		reverse = reverse << 1;
		reverse = reverse | (x & 1);
		x = x >> 1;
	}
    return reverse;
}

block_t shuffle4(block_t x)
{
	block_t result = 0;
	for (int i = 3; i >= 0; i--){
		result |= (x & (0xF << (4*(4+i)))) >> (4 * (3-i));
		result |= (x & (0xF << (4*i))) << (4 * i);	
	}
    return result;
}

block_t unshuffle4(block_t x)
{
	block_t result = 0;
	for (int i = 3; i >= 0; i--){
		result |= (x & (0xF << (4*(1+i+i)))) << (4*(3-i));
		result |= (x & (0xF << (4*(i+i)))) >> (4*i);
	}
	return result;
}

block_t shuffle1(block_t x)
{
	block_t result = 0;
	for (int i = 15; i >= 0; i--){
		result |= (x & (0x1 << (16+i))) >> (16-i-1);
		result |= (x & (0x1 << i)) << i;
	}
    return result;
}

block_t unshuffle1(block_t x)
{
	block_t result = 0;
	for (int i = 15; i >= 0; i--){
		result |= (x & (0x1 << (1+i+i))) << (16-i-1);
		result |= (x & (0x1 << (i+i))) >> i;
	}
    return result;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
	return (x >> 8*(n%4)) & 0xFF;
}

// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{	
	expanded_keys[0] = key & 0xFFFFFFFF;
	expanded_keys[1] = (key & 0xFFFFFFFF00000000) >> 32;
	for (int i = 2; i < 32; i++)
		expanded_keys[i] = table[(expanded_keys[i - 1] ^ expanded_keys[i - 2]) % 64] ^ expanded_keys[i - 1];
	for (int i = 29; i >= 0; i--)
		expanded_keys[i] = table[(expanded_keys[i + 1] ^ expanded_keys[i + 2]) % 64] ^ expanded_keys[i];
}

int rot_table[] = { 2, 3, 5, 7 };

uint8_t scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB)
{
    block_t B1 = nth_byte(B, i) ^ (nth_byte(B, i-1) & nth_byte(B, i-2)) ^ ( ~nth_byte(B, i-1) & nth_byte(B, i-3)) ^ nth_byte(keyA, i) ^ nth_byte(keyB, i);
    return rotl(B1, rot_table[i]);
}

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	block_t keyA = keys[round];
	block_t keyB = keys[31-round];
	x = op(x);
	x = (x & ~0x000000FF) | scramble_op(x, 0, keyA, keyB);    
    x = (x & ~0x0000FF00) | (scramble_op(x, 1, keyA, keyB) << 8);    
    x = (x & ~0x00FF0000) | (scramble_op(x, 2, keyA, keyB) << 16);   
    x = (x & ~0xFF000000) | (scramble_op(x, 3, keyA, keyB) << 24);  
    return x;
}

uint8_t mash_op(block_t B, uint8_t i, block_t *S){
    block_t key = S[nth_byte(B, i-1)%32];
    return nth_byte(B, i) ^ nth_byte(key, i);
}

block_t mash(block_t x, block_t *keys)
{
	x = (x & ~0x000000FF) | mash_op(x, 0, keys);
    x = (x & ~0x0000FF00) | (mash_op(x, 1, keys) << 8);
    x = (x & ~0x00FF0000) | (mash_op(x, 2, keys) << 16);
    x = (x & ~0xFF000000) | (mash_op(x, 3, keys) << 24); 
    return x;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
	// (void) plain_text;
	// plain_text = 0x739192b5;
	// printf("Current (R00): %x\n", plain_text);
	block_t R01 = scramble(plain_text, expanded_keys, 0, reverse);
	// printf("R01: %x\n", R01);
	// block_t R01 = 0x7b57fb16;
	// printf("R01: %x\n", R01);
	block_t R02 = scramble(R01, expanded_keys, 1, shuffle1);
	// printf("R02: %x\n", R02);
	// block_t R02 = 0x17a08711;
	// printf("R02: %x\n", R02);
	block_t R03 = scramble(R02, expanded_keys, 2, shuffle4);
	// printf("R03: %x\n", R03);
	block_t R04 = scramble(R03, expanded_keys, 3, reverse);
	// printf("R04: %x\n", R04);
	block_t R05 = mash(R04, expanded_keys);
	// printf("R05: %x\n", R05);

	block_t R06 = scramble(R05, expanded_keys, 4, reverse);
	block_t R07 = scramble(R06, expanded_keys, 5, shuffle1);
	block_t R08 = scramble(R07, expanded_keys, 6, shuffle4);
	block_t R09 = scramble(R08, expanded_keys, 7, reverse);
	block_t R10 = mash(R09, expanded_keys);

	block_t R11 = scramble(R10, expanded_keys, 8, reverse);
	block_t R12 = scramble(R11, expanded_keys, 9, shuffle1);
	block_t R13 = scramble(R12, expanded_keys, 10, shuffle4);
	block_t R14 = scramble(R13, expanded_keys, 11, reverse);
	block_t R15 = mash(R14, expanded_keys);

	block_t R16 = scramble(R15, expanded_keys, 12, reverse);
	block_t R17 = scramble(R16, expanded_keys, 13, shuffle1);
	block_t R18 = scramble(R17, expanded_keys, 14, shuffle4);
	block_t R19 = scramble(R18, expanded_keys, 15, reverse);
	// printf("R19: %x\n", R19);


    return R19;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	(void) x;
	(void) keys;
	(void) round;
	(void) op;

    return 0;
}

block_t r_mash(block_t x, block_t *keys)
{
	(void) x;
	(void) keys;
	return 0;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
	(void) cipher_text;
	(void) expanded_keys;
	return 0;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
	// *encrypted_output = (block_t*) calloc(ceil(pt_len / 4.0), sizeof(block_t));
	block_t current = 0;
	int offset = (4 - (pt_len % 4)) % 4;

	for (size_t i = 0; i < (pt_len+offset); i+=4){
		current = 
			plaintext_input[i]									|
			(((i+1) < pt_len) ? plaintext_input[i+1] : 0) << 8	|
			(((i+2) < pt_len) ? plaintext_input[i+2] : 0) << 16	|
			(((i+3) < pt_len) ? plaintext_input[i+3] : 0) << 24	
			;
			
		encrypted_output[i/4] = sbu_encrypt_block(current, expanded_keys);
		// printf("ENCRYPTED BLOCK %lu: %x\n", i/4, encrypted_output[i/4]);
	}
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
	(void) encrypted_input;
	(void) plaintext_output;
	(void) pt_len;
	(void) expanded_keys;
}

// ----------------- Utility Functions ----------------- //