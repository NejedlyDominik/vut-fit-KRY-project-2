/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 * 
 * @brief Program entry point module
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "args.h"
#include "input.h"
#include "sha256.h"


#define EXIT_NO_PARAMS 1
#define EXIT_VALID_MAC 0
#define EXIT_INVALID_MAC 1


/**
 * Based on the command line arguments compute SHA-256 checksum of the input message and print,
 * it to the standard output, compute MAC of the input message and print it to the standard output,
 * verify the MAC for the given secret key and input message, perform the length extension attack
 * on the given MAC and input message, or print usage of the program to the standard output.
 * 
 * @param argc The number of command line arguments
 * @param argv Values of command line arguments
 * 
 * @return 0 in case of successful run of the program or successul MAC verification, 1 otherwise.
 */
int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_usage();
        return EXIT_NO_PARAMS;
    }

    char functionality, *key, *chs, *msg;
    uint64_t num;

    if (!parse_args(argc, argv, &functionality, &key, &chs, &num, &msg)) {
        return EXIT_FAILURE;
    }

    data_container_t input_msg;
    init_container(&input_msg);

    if (functionality == 's' || functionality == 'v') {
        if (!extend_container(&input_msg, key)) {
            return EXIT_FAILURE;
        }
    }

    if (!load_input(stdin, &input_msg)) {
        return EXIT_FAILURE;
    }

    char hash[65];

    if (functionality == 'c' || functionality == 's') {
        sha256(input_msg.buffer, input_msg.data_len, hash, NULL, 0);
        printf("%s\n", hash);
    }
    else if (functionality == 'v') {    
        sha256(input_msg.buffer, input_msg.data_len, hash, NULL, 0);
        reset_container(&input_msg);

        // Verify hash case insesitively
        for (uint8_t i = 0; i < 64; i++) {
            if (tolower(chs[i]) != tolower(hash[i])) {
                return EXIT_INVALID_MAC;
            }
        }

        return EXIT_VALID_MAC;
    }
    else {
        sha256(msg, strlen(msg), hash, chs, get_padded_msg_len(input_msg.data_len + num));
        printf("%s\n", hash);
        print_padded_msg(input_msg.buffer, input_msg.data_len, num, msg);
    }

    reset_container(&input_msg);
    return EXIT_SUCCESS;
}
