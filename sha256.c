/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 * 
 * @brief SHA-256 module
 */


#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "sha256.h"


#define DWORD_BIT_LEN 32
#define BYTE_BIT_LEN 8

#define BLOCK_SIZE 64
#define MSG_DELIMITER 128
#define RESERVED_LEN_BYTE_COUNT 8

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SHR(x, n) ((x) >> (n))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (DWORD_BIT_LEN - (n)))) 

#define Sigma_0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma_1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma_0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma_1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))


/**
 * @struct Message processing state internal representation
 */
typedef struct msg_t {
    const uint8_t *data;
    uint64_t len;
    uint64_t processed_len;
    uint64_t init_hash_offset;
    bool processed;
} msg_t;


/**
 * Initialize message processing state.
 * 
 * @param msg Message processing state to be initialized
 * @param data Message data
 * @param len Length of message data (in bytes)
 * @param init_hash_offset The given number of already processed bytes of the message corresponding to the given SHA-256 initial hash
 */
void init_msg(msg_t *msg, const void *data, uint64_t len, uint64_t init_hash_offset) {
    msg->data = data;
    msg->len = len;
    msg->processed_len = 0;
    msg->init_hash_offset = init_hash_offset;
    msg->processed = false;
}


/**
 * Convert unsigned 64 bit integer to corresponding array of 8 unsigned 8 bit integers.
 * 
 * @param arr The location to store the resulting 8 unsigned 8 bit integers
 * @param num The original unsigned 64 bit integer
 */
void uint64_to_byte_array(uint8_t *arr, uint64_t num) {
    arr[0] = (uint8_t) (num >> 56);
    arr[1] = (uint8_t) (num >> 48);
    arr[2] = (uint8_t) (num >> 40);
    arr[3] = (uint8_t) (num >> 32);
    arr[4] = (uint8_t) (num >> 24);
    arr[5] = (uint8_t) (num >> 16);
    arr[6] = (uint8_t) (num >> 8);
    arr[7] = (uint8_t) num;
}


/**
 * Get the next 512 bit block of the given message.
 * 
 * @param msg Message processing state of the given message
 * @param msg_block The location to store the next padded message block
 * 
 * @return True if the next block of the given message is successfuly prepared, false if the whole message is already processed.
 */
bool get_next_block(msg_t *msg, uint8_t *msg_block) {
    if (msg->processed) {
        return false;
    }

    if (msg->processed_len + BLOCK_SIZE <= msg->len) {
        memcpy(msg_block, msg->data + msg->processed_len, BLOCK_SIZE);
    }
    else {
        memset(msg_block, 0, BLOCK_SIZE);

        if (msg->processed_len <= msg->len) {
            // From standard is not completely clear if memcpy source pointer can point to one-past-last element with count set to 0
            if (msg->processed_len < msg->len) {
                memcpy(msg_block, msg->data + msg->processed_len, msg->len - msg->processed_len);
            }

            msg_block[msg->len - msg->processed_len] = MSG_DELIMITER;
        }

        if (msg->processed_len + BLOCK_SIZE > msg->len + RESERVED_LEN_BYTE_COUNT) {
            uint64_to_byte_array(msg_block + BLOCK_SIZE - RESERVED_LEN_BYTE_COUNT, (msg->len + msg->init_hash_offset) * BYTE_BIT_LEN);
            msg->processed = true;
        }
    }

    msg->processed_len += BLOCK_SIZE;
    return true;
}


void sha256(const void *msg_data, uint64_t msg_len, char *result_hash, char *init_hash, uint64_t init_hash_offset) {
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t H_0, H_1, H_2, H_3, H_4, H_5, H_6, H_7;

    H_0 = 0x6a09e667;
    H_1 = 0xbb67ae85;
    H_2 = 0x3c6ef372;
    H_3 = 0xa54ff53a;
    H_4 = 0x510e527f;
    H_5 = 0x9b05688c;
    H_6 = 0x1f83d9ab;
    H_7 = 0x5be0cd19;

    if (init_hash != NULL) {
        sscanf(init_hash, "%08x%08x%08x%08x%08x%08x%08x%08x", &H_0, &H_1, &H_2, &H_3, &H_4, &H_5, &H_6, &H_7);
    }

    uint8_t msg_block[BLOCK_SIZE];
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T_1, T_2;
    msg_t msg;

    init_msg(&msg, msg_data, msg_len, init_hash_offset);

    while (get_next_block(&msg, msg_block)) {
        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
            W[i] = (uint32_t) msg_block[j] << 24 |
                (uint32_t) msg_block[j + 1] << 16 |
                (uint32_t) msg_block[j + 2] << 8 |
                (uint32_t) msg_block[j + 3];
        }

        for (uint8_t i = 16; i < 64; i++) {
            W[i] = sigma_1(W[i - 2]) + W[i - 7] + sigma_0(W[i - 15]) + W[i - 16];
        }

        a = H_0;
        b = H_1;
        c = H_2;
        d = H_3;
        e = H_4;
        f = H_5;
        g = H_6;
        h = H_7;

        for (uint8_t i = 0; i < 64; i++) {
            T_1 = h + Sigma_1(e) + Ch(e, f, g) + K[i] + W[i];
            T_2 = Sigma_0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T_1;
            d = c;
            c = b;
            b = a;
            a = T_1 + T_2;
        }

        H_0 += a;
        H_1 += b;
        H_2 += c;
        H_3 += d;
        H_4 += e;
        H_5 += f;
        H_6 += g;
        H_7 += h;
    }

    sprintf(result_hash, "%08x%08x%08x%08x%08x%08x%08x%08x", H_0, H_1, H_2, H_3, H_4, H_5, H_6, H_7);
}


uint64_t get_padded_msg_len(uint64_t msg_len) {
    return (msg_len / BLOCK_SIZE + ((msg_len % BLOCK_SIZE < BLOCK_SIZE - RESERVED_LEN_BYTE_COUNT) ? 1 : 2)) * BLOCK_SIZE;
}


void print_padded_msg(const void *msg_data, uint64_t msg_len, uint64_t offset, char *extension) {
    const char *msg_p = msg_data;

    for (uint64_t i = 0; i < msg_len; i++) {
        printf("%c", msg_p[i]);
    }

    printf("\\x80");

    uint8_t zero_byte_count = (uint8_t) (get_padded_msg_len(msg_len + offset) - msg_len - 1 - offset - RESERVED_LEN_BYTE_COUNT);

    for (uint8_t i = 0; i < zero_byte_count; i++) {
        printf("\\x00");
    }

    uint8_t msg_bit_length_byte_arr[8];
    uint64_to_byte_array(msg_bit_length_byte_arr, (offset + msg_len) * 8);

    for (uint8_t i = 0; i < 8; i++) {
        printf("\\x%02x", msg_bit_length_byte_arr[i]);
    }

    if (extension != NULL) {
        printf("%s\n", extension);
    }
    else {
        printf("\n");
    }
}
