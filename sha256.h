/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 * 
 * @brief SHA-256 interface
 */


#ifndef SHA256_H
#define SHA256_H


#include <stdint.h>


/**
 * Compute SHA-256 of the given message.
 * 
 * @param msg_data The given message to be processed
 * @param msg_len The length of the given message
 * @param result_hash The location to store the resulting hash
 * @param init_hash The given SHA-256 initial hash
 * @param init_hash_offset The given number of already processed bytes corresponding of the message to the given SHA-256 initial hash
 */
void sha256(const void *msg_data, uint64_t msg_len, char *result_hash, char *init_hash, uint64_t init_hash_offset);

/**
 * Get the length of the padded message.
 * 
 * @param msg_len The length of the original message
 * 
 * @return The length of the padded message.
 */
uint64_t get_padded_msg_len(uint64_t msg_len);

/**
 * Print the padded message.
 * 
 * @param msg_data The given original message
 * @param msg_len The length of the given original message
 * @param offset The number of bytes preceding the given original message
 * @param extension The extension of the padded message
 */
void print_padded_msg(const void *msg_data, uint64_t msg_len, uint64_t offset, char *extension);


#endif
