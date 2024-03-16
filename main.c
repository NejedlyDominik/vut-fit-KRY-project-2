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
        sha256(msg, strlen(msg), hash, chs, get_padded_msg_len(input_msg.data_len));
        printf("%s\n", hash);
        print_padded_msg(input_msg.buffer, input_msg.data_len, num, msg);
    }

    reset_container(&input_msg);
    return EXIT_SUCCESS;
}
