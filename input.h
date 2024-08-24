/**
 * VUT FIT KRY - Project 2 - MAC using SHA-256 & Length extension attack
 *
 * @author Dominik Nejedlý (xnejed09)
 * @date 16. 3. 2024
 *
 * @brief Program input loading and manipulation interface
 */


#ifndef INPUT_H
#define INPUT_H


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


/**
 * @struct Dynamic byte container representation
 */
typedef struct data_container_t {
    uint8_t *buffer;
    uint64_t data_len;
    uint64_t buffer_size;
} data_container_t;


/**
 * Initialize dynamic byte container.
 * 
 * @param container The container to be initialized
 */
void init_container(data_container_t *container);

/**
 * Reinitialize the container (including freeing its buffer).
 * 
 * @param container The container to be reinitialized
 */
void reset_container(data_container_t *container);

/**
 * Append the given string to the end of the given container.
 * 
 * @param container The container to be extended
 * @param extension The string to be appended to the end of container
 * 
 * @return True if the given string is successfully appended to the end of given container, false otherwise.
 */
bool extend_container(data_container_t *container, char *extension);

/**
 * Load input to the end of the container.
 * 
 * @param input_stream Input file stread to read from
 * @param container The container to be extended by the input data
 * 
 * @return True if the input data are successfully appended to the end of given container, false otherwise.
 */
bool load_input(FILE *input_stream, data_container_t *container);


#endif
