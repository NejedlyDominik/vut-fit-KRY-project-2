/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 * 
 * @brief Processing of the command line arguments module
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include "args.h"


#define CHS_LEN 64


void print_usage(void) {
    printf("KRY - Project 2 - MAC using SHA-256 & Length extension attack\n\n");
    printf("Usage:\n");
    printf("  ./kry [-c|-s|-v|-e] [-k KEY] [-m CHS] [-n NUM] [-a MSG]\n\n");
    printf("Note:\n");
    printf("  The input message is read from STDIN. When the program is run without command line arguments,\n");
    printf("  it prints its usage documentation to standard output and exits with return code 1.\n\n");
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
                // Check the format of secret key: ^[A-Za-z0-9]*$
                for (char *c_ptr = optarg; *c_ptr != '\0'; c_ptr++) {
                    if (!((*c_ptr >= 48 && *c_ptr <= 57) || (*c_ptr >= 65 && *c_ptr <= 90) || (*c_ptr >= 97 && *c_ptr <= 122))) {
                        fprintf(stderr, "Invalid format of parameter -k: '%s' -- expected format: ^[A-Za-z0-9]*$\n", optarg);
                        return false;
                    }
                }

                *key = optarg;
                break;
            case 'm':
                // Check the format of MAC (checksum): ^[A-Fa-f0-9]{64}$
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
                // Check the format of the input message extension: ^[a-zA-Z0-9!#$%&'"()*+,-./:;<>=?@[]\^_{}|~]*$)\n"
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
