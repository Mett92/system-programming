#ifndef _MIME_TYPE_UTILITY_H_
#define _MIME_TYPE_UTILITY_H_

// LUNGHEZZA MASSIMA DI UNA STRINGA DI TIPO MIMETYPE
#define MAX_LEN_MIMETYPE 50

// MIMETYPE NAME
#define TEXT_PLAIN "text/plain"															// Standard text for body contenente l'output di un comando
#define APPL_ZIP "application/zip"

//TIPO MIMETYPE
typedef char *MIMETYPE;

/*
 *  Dato un file con path file_name, la funzione inserisce 
 *      il mymetype nell'array puntato da *mimetype.
 * 
 *  @Return:
 *      booleano: 0 se non trovato, 1 altrimenti.
 */
int get_file_mimetype(char *file_name, MIMETYPE mimetype);

#endif