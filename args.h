/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 *
 * @brief Processing of the command line arguments interface
 */


#ifndef ARGS_H
#define ARGS_H


#include <stdint.h>
#include <stdbool.h>


/**
 * Print usage of the program to standard output.
 */
void print_usage(void);

/**
 * Parse command line arguments.
 * 
 * @param argc The number of command line arguments
 * @param argv Values of command line arguments
 * @param functionality The location to store the chosen program functionality
 * @param key The location to store the pointer to the chosen secret key for MAC calculation
 * @param chs The location to store the pointer to the chosen MAC (checksum) to verify it or perform a length extension attack
 * @param num The location to store the chosen length of secret key to perform a length extension attack
 * @param msg The location to store the pointer to the chosen extension of the input message to perform a length extension attack
 * 
 * @return True in case of successul parse, false otherwise (in case of ivalid usage of command line arguments).
 */
bool parse_args(int argc, char *argv[], char *functionality, char **key, char **chs, uint64_t *num, char **msg);


#endif
