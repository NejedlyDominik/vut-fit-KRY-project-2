#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "args.h"
#include "input.h"
#include "sha256.h"

#define EXIT_NO_PARAMS 1
#define EXIT_VALID_MAC 0
#define EXIT_INVALID_MAC 1


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

        if (strcmp(chs, hash) == 0) {
            return EXIT_VALID_MAC;
        }

        return EXIT_INVALID_MAC;
    }
    else {
        uint64_t padded_msg_len = get_padded_msg_len(input_msg.data_len);
        sha256(msg, strlen(msg), hash, chs, padded_msg_len);
        printf("%s\n", hash);

        for (uint64_t i = 0; i < input_msg.data_len; i++) {
            printf("%c", input_msg.buffer[i]);
        }

        printf("\\x80");

        for (uint64_t i = input_msg.data_len + 1; i < padded_msg_len - 8; i++) {
            printf("\\x00");
        }

        uint8_t msg_bit_length_byte_arr[8];
        uint64_to_byte_array(msg_bit_length_byte_arr, (num + input_msg.data_len) * 8);

        for (uint8_t i = 0; i < 8; i++) {
            printf("\\x%02x", msg_bit_length_byte_arr[i]);
        }

        printf("%s\n", msg);
    }

    reset_container(&input_msg);
    return EXIT_SUCCESS;
}
