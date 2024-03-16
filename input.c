#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "input.h"


#define CHUNK_SIZE 64


void init_container(data_container_t *container) {
    container->buffer = NULL;
    container->data_len = 0;
    container->buffer_size = 0;
}


void reset_container(data_container_t *container) {
    free(container->buffer);
    init_container(container);
}


bool extend_container_buffer(data_container_t *container, uint64_t extension_size) {
    uint8_t *tmp_buffer;

    if ((tmp_buffer = realloc(container->buffer, container->buffer_size + extension_size)) == NULL) {
        reset_container(container);
        fprintf(stderr, "Internal memory error\n");
        return false;
    }

    container->buffer_size += extension_size;
    container->buffer = tmp_buffer;
    return true;
}


bool extend_container(data_container_t *container, char *extension) {
    size_t extension_len = strlen(extension);

    if (container->data_len + extension_len > container->buffer_size) {
        if (!extend_container_buffer(container, container->data_len + extension_len - container->buffer_size)) {
            return false;
        }
    }

    memcpy(container->buffer + container->data_len, extension, extension_len);
    container->data_len += extension_len;
    return true;
}


bool load_input(FILE *input_stream, data_container_t *container) {
    int c;

    while ((c = fgetc(input_stream)) != EOF) {

        if (container->data_len >= container->buffer_size) {
            if (!extend_container_buffer(container, CHUNK_SIZE)) {
                return false;
            }
        }

        container->buffer[container->data_len++] = (uint8_t) c;
    }

    if (ferror(input_stream)) {
        reset_container(container);
        fprintf(stderr, "Input reading error\n");
        return false;
    }

    return true;
}
