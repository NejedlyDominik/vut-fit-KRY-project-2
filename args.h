#ifndef ARGS_H
#define ARGS_H


#include <stdint.h>
#include <stdbool.h>


void print_usage(void);
bool parse_args(int argc, char *argv[], char *functionality, char **key, char **chs, uint64_t *num, char **msg);


#endif
