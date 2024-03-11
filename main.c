#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>


#define CHUNK_SIZE 512
#define RESERVED_BYTE_COUNT 8

#define EXIT_NO_PARAMS 1
#define EXIT_VALID_MAC 0
#define EXIT_INVALID_MAC 1


const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void print_usage(void) {
    printf("KRY - Project 2 - MAC using SHA-256 & Length extension attack\n\n");
    printf("Usage:\n");
    printf("  ./kry -c|-s|-v|-e [-k KEY] [-m CHS] [-n NUM] [-a MSG]\n\n");
    printf("Note:\n");
    printf("  The input message is read from STDIN\n\n");
    printf("Mutually exclusive options:\n");
    printf("  -c        compute SHA-256 checksum of the input message and print it to STDOUT\n");
    printf("  -s        compute MAC for the input message using SHA-256 and print it to STDOUT\n");
    printf("            (must be used with parameter -k)\n");
    printf("  -v        verifie the MAC for the given key and input message and return 0 if MAC is valid\n");
    printf("            or 1 otherwise (must be used with parameters -k and -m)\n");
    printf("  -e        performs the length extension attack on the MAC and input message and print\n");
    printf("            the recoputed MAC and extended message to STDOUT (must be used with parameters -m, -n and -a)\n\n");
    printf("Additional parameters:\n");
    printf("  -k KEY    specify the secret key for the MAC calculation (KEY expected format: ^[A-Za-z0-9]*$)\n");
    printf("  -m CHS    specify the MAC of the input message to verify it or perform the attack\n");
    printf("  -n NUM    specify the length of the secret key to perform the attack\n");
    printf("  -a MSG    specify the extension of the input message to perform the attack\n");
    printf("            (MSG expected format: ^[a-zA-Z0-9!#$%%&'\"()*+,-./:;<>=?@[]\\^_{}|~]*$)\n");
}


bool parse_args(int argc, char *argv[], char *functionality, char **key, char **chs, uint64_t *num, char **msg) {
    int opt;
    *functionality = '\0';
    *key = NULL;
    *chs = NULL;
    *msg = NULL;
    char *endptr;
    bool num_is_defined = false;

    while ((opt = getopt(argc, argv, "csvek:m:n:a:")) != -1) {
        switch (opt) {
            case 'c':
            case 's':
            case 'v':
            case 'e':
                if (*functionality != '\0' && *functionality != opt) {
                    fprintf(stderr, "Options -%c and -%c cannot be used at the same time\n", *functionality, opt);
                    return false;
                }

                *functionality = opt;
                break;
            case 'k':
                for (char *c_ptr = optarg; *c_ptr != '\0'; c_ptr++) {
                    if (!((*c_ptr >= 48 && *c_ptr <= 57) || (*c_ptr >= 65 && *c_ptr <= 90) || (*c_ptr >= 97 && *c_ptr <= 122))) {
                        fprintf(stderr, "Invalid format of parameter -k: '%s' -- expected format: ^[A-Za-z0-9]*$\n", optarg);
                        return false;
                    }
                }

                *key = optarg;
                break;
            case 'm':
                *chs = optarg;
                break;
            case 'n':
                *num = strtoull(optarg, &endptr, 0);

                if (*endptr != '\0') {
                    fprintf(stderr, "Invalid value of parameter -n: '%s' -- a non-negative number is expected\n", optarg);
                    return false;
                }

                if (errno == ERANGE) {
                    fprintf(stderr, "Range error of parameter -n: '%s' -- key length is too large\n", optarg);
                    return false;
                }

                num_is_defined = true;
                break;
            case 'a':
                for (char *c_ptr = optarg; *c_ptr != '\0'; c_ptr++) {
                    if (!((*c_ptr >= 33 && *c_ptr <= 95) || (*c_ptr >= 97 && *c_ptr <= 126))) {
                        fprintf(stderr, "Invalid format of parameter -a: '%s' -- expected format: ^[a-zA-Z0-9!#$%%&'\"()*+,-./:;<>=?@[]\\^_{}|~]*$\n", optarg);
                        return false;
                    }
                }

                *msg = optarg;
                break;
        }
    }

    if (*functionality == 's') {
        if (*key == NULL) {
            fprintf(stderr, "Option -s must be used in combination with parameter -k\n");
            return false;
        }
    }
    else if (*functionality == 'v') {
        if (*key == NULL || *chs == NULL) {
            fprintf(stderr, "Option -v must be used in combination with parameters -k and -m\n");
            return false;
        }
    }
    else if (*functionality == 'e') {
        if (*chs == NULL || !num_is_defined || *msg == NULL) {
            fprintf(stderr, "Option -e must be used in combination with parameters -m, -n and -a\n");
            return false;
        }
    }
    else if (*functionality == '\0') {
        fprintf(stderr, "No functionality of application specified -- one of the following options is expected: -c, -s, -v, -e\n");
        return false;
    }

    return true;
}


uint8_t *extend_buffer(uint8_t *buffer, uint64_t buffer_size, uint64_t extension_size) {
    uint8_t *new_buffer;

    if ((new_buffer = realloc(buffer, buffer_size + extension_size)) == NULL) {
        free(buffer);
        fprintf(stderr, "Internal memory error\n");
    }

    return new_buffer;
}


uint8_t *load_and_pad_msg(FILE *input_stream) {
    uint8_t *buffer = NULL;
    uint64_t buffer_content_len = 0, buffer_size = 0;

    do {
        if ((buffer = extend_buffer(buffer, buffer_size, CHUNK_SIZE)) == NULL) {
            return NULL;
        }

        buffer_content_len += fread(buffer + buffer_content_len, 1, CHUNK_SIZE, input_stream);
        buffer_size += CHUNK_SIZE;
    } while (buffer_content_len == buffer_size);

    if (ferror(input_stream)) {
        free(buffer);
        fprintf(stderr, "Input reading error\n");
        return NULL;
    }

    if (buffer_content_len >= buffer_size - RESERVED_BYTE_COUNT) {
        if ((buffer = extend_buffer(buffer, buffer_size, CHUNK_SIZE)) == NULL) {
            return NULL;
        }
    }

    buffer[buffer_content_len] = 1<<7;
    memset(buffer + buffer_content_len, 0, buffer_size - buffer_content_len - RESERVED_BYTE_COUNT);

    uint64_t buffer_content_bit_len = buffer_content_len * 8;
    memcpy(buffer + buffer_size - RESERVED_BYTE_COUNT, &buffer_content_bit_len, RESERVED_BYTE_COUNT);

    return buffer;
}


//void sha256(uint8_t *msg, uint32_t *hash) {
//    
//}


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

    uint8_t *padded_input_msg = load_and_pad_msg(stdin);

    if (padded_input_msg == NULL) {
        return EXIT_FAILURE;
    }

    free(padded_input_msg);
    return EXIT_SUCCESS;
}
