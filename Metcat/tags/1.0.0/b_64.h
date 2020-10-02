

#ifndef _B_64_H_
#define _B_64_H_

#ifndef _STDLIB_H
#include <stdlib.h>
#endif

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

/*  
 *  NOTA: liberare memoria ritornata e chiamare base64_cleanup() spetta al chiamante
 */
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

void build_decoding_table();

void base64_cleanup();

#endif