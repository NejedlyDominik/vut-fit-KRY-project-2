#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#define BLOCK_SIZE 64

#define CHUNK_SIZE 64
#define RESERVED_LEN_BYTE_COUNT 8

#define CHS_LEN 64

#define MSG_DELIMITER 128

#define BYTE_BIT_LEN 8
#define DWORD_BIT_LEN 32

#define EXIT_NO_PARAMS 1
#define EXIT_VALID_MAC 0
#define EXIT_INVALID_MAC 1


#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SHR(x, n) ((x) >> (n))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (DWORD_BIT_LEN - (n)))) 

#define Sigma_0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma_1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma_0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma_1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))


typedef struct msg_t {
    uint8_t *buffer;
    uint64_t msg_len, buffer_size, elongation;
} msg_t;


void init_msg(msg_t *msg) {
    msg->buffer = NULL;
    msg->msg_len = 0;
    msg->buffer_size = 0;
    msg->elongation = 0;
}


void destruct_msg(msg_t *msg) {
    free(msg->buffer);
}


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
    printf("            (CHS expected format: ^[A-Fa-f0-9]{%u}$)\n", CHS_LEN);
    printf("  -n NUM    specify the length of the secret key to perform the attack\n");
    printf("  -a MSG    specify the extension of the input message to perform the attack\n");
    printf("            (MSG expected format: ^[a-zA-Z0-9!#$%%&'\"()*+,-./:;<>=?@[]\\^_{}|~]*$)\n");
}


bool parse_args(int argc, char *argv[], char *functionality, char **key, char **chs, uint64_t *num, char **msg) {
    int opt;
    *functionality = '\0';
    *key = NULL;
    *chs = NULL;
    uint8_t chs_len = 0;
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
                for (char *c_ptr = optarg; *c_ptr != '\0'; c_ptr++) {
                    if (!((*c_ptr >= 48 && *c_ptr <= 57) || (*c_ptr >= 65 && *c_ptr <= 70) || (*c_ptr >= 97 && *c_ptr <= 102))) {
                        fprintf(stderr, "Invalid format of parameter -m: '%s' -- expected format: ^[A-Fa-f0-9]{%u}$\n", optarg, CHS_LEN);
                        return false;
                    }

                    if(++chs_len > CHS_LEN) {
                        break;
                    }
                }

                if (chs_len != CHS_LEN) {
                    fprintf(stderr, "Invalid length of parameter -m: %u -- expected format: ^[A-Fa-f0-9]{%u}$\n", chs_len, CHS_LEN);
                    return false;
                }

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


bool extend_msg_buffer(msg_t *msg, uint64_t extension_size) {
    uint8_t *tmp_buffer;

    if ((tmp_buffer = realloc(msg->buffer, msg->buffer_size + extension_size)) == NULL) {
        free(msg->buffer);
        fprintf(stderr, "Internal memory error\n");
        return false;
    }

    msg->buffer_size += extension_size;
    msg->buffer = tmp_buffer;
    return true;
}


bool extend_msg(msg_t *msg, char *extension) {
    size_t extension_len = strlen(extension);

    while(msg->buffer_size < extension_len) {
        if (!extend_msg_buffer(msg, CHUNK_SIZE)) {
            return false;
        }
    }

    memcpy(msg->buffer + msg->msg_len, extension, extension_len);
    msg->msg_len += extension_len;
    return true;
}


bool load_and_pad_msg(FILE *input_stream, msg_t *msg) {
    msg->msg_len += fread(msg->buffer + msg->msg_len, 1, msg->buffer_size - msg->msg_len, input_stream);

    while (msg->msg_len == msg->buffer_size) {
        if (!extend_msg_buffer(msg, CHUNK_SIZE)) {
            return false;
        }

        msg->msg_len += fread(msg->buffer + msg->msg_len, 1, CHUNK_SIZE, input_stream);
    }

    if (ferror(input_stream)) {
        free(msg->buffer);
        fprintf(stderr, "Input reading error\n");
        return false;
    }

    return true;
}


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


bool get_next_block(msg_t *msg, uint8_t *msg_block, uint64_t offset) {
    if (offset + BLOCK_SIZE <= msg->msg_len) {
        memcpy(msg_block, msg->buffer + offset, BLOCK_SIZE);
        return true;
    }

    memset(msg_block, 0, BLOCK_SIZE);

    if (offset < msg->msg_len) {
        memcpy(msg_block, msg->buffer + offset, msg->msg_len - offset);
        msg_block[msg->msg_len - offset] = MSG_DELIMITER;
    }

    if (offset + BLOCK_SIZE <= msg->msg_len + RESERVED_LEN_BYTE_COUNT) {
        return true;
    }

    uint64_t msg_bit_len = (msg->msg_len + msg->elongation) * BYTE_BIT_LEN;

    msg_block[BLOCK_SIZE - 1] = msg_bit_len;
    msg_block[BLOCK_SIZE - 2] = msg_bit_len >> 8;
    msg_block[BLOCK_SIZE - 3] = msg_bit_len >> 16;
    msg_block[BLOCK_SIZE - 4] = msg_bit_len >> 24;
    msg_block[BLOCK_SIZE - 5] = msg_bit_len >> 32;
    msg_block[BLOCK_SIZE - 6] = msg_bit_len >> 40;
    msg_block[BLOCK_SIZE - 7] = msg_bit_len >> 48;
    msg_block[BLOCK_SIZE - 8] = msg_bit_len >> 56;

    return false;
}


void sha256(msg_t *msg, char *result_hash, char *init_hash) {
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
    bool process_next_block = true;
    uint64_t block_offset = 0;

    while (process_next_block) {
        process_next_block = get_next_block(msg, msg_block, block_offset);
        block_offset += BLOCK_SIZE;

        for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
            W[i] = (msg_block[j] << 24) | (msg_block[j + 1] << 16) | (msg_block[j + 2] << 8) | msg_block[j + 3];
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

    msg_t padded_msg;
    init_msg(&padded_msg);

    if (functionality == 's' || functionality == 'v') {
        if (!extend_msg(&padded_msg, key)) {
            return EXIT_FAILURE;
        }
    }

    if (!load_and_pad_msg(stdin, &padded_msg)) {
        return EXIT_FAILURE;
    }

    char hash[65];

    if (functionality == 'c' || functionality == 's') {
        sha256(&padded_msg, hash, NULL);
        printf("%s\n", hash);
    }
    else if (functionality == 'v') {    
        sha256(&padded_msg, hash, NULL);

        if (strcmp(chs, hash) == 0) {
            return EXIT_VALID_MAC;
        }

        return EXIT_INVALID_MAC;
    }
    else {
        msg_t new_msg = {msg, strlen(msg), 0, 64};
        sha256(&new_msg, hash, chs);
        printf("%s\n", hash);
    }

    destruct_msg(&padded_msg);
    return EXIT_SUCCESS;
}
