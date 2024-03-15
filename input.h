#ifndef INPUT_H
#define INPUT_H


#include <stdio.h>
#include <stdint.h>


typedef struct data_container_t {
    uint8_t *buffer;
    uint64_t data_len;
    uint64_t buffer_size;
} data_container_t;


void init_container(data_container_t *container);
void reset_container(data_container_t *container);
bool extend_container(data_container_t *container, char *extension);
bool load_input(FILE *input_stream, data_container_t *container);


#endif
