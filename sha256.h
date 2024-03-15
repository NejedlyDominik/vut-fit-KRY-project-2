#ifndef SHA256_H
#define SHA256_H


#include <stdint.h>


void uint64_to_byte_array(uint8_t *arr, uint64_t num);
void sha256(void *msg_data, uint64_t msg_data_len, char *result_hash, char *init_hash, uint64_t init_hash_offset);
uint64_t get_padded_msg_len(uint64_t msg_len);


#endif
