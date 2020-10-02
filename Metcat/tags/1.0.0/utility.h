/*
 * utilityFunction.h
 * ServerApp
 * 
 * Gestisce la stampa a degli errori
 * 
 *  Created by Mattia Paolacci
 */
#ifndef _UTILITY_H_
#define _UTILITY_H_

#include "list.h"
#include "http_utility.h"
#include <time.h>

#ifndef _WIN32
#include <sys/un.h>
#include <stdio.h>
#else
#include <winsock2.h>
#endif

typedef char *WIN_PATH;
typedef int URI_TYPE;                               // Tipo di dato che rappresenta un URI all'interno del server
typedef char *CMD;
typedef char *PATH;

// COSTANTI DI SISTEMA
#define KEY_CMD_REQ "command"                      // STRINGA RICHIESTA, PER ESEGUIRE UN COMANDO, COME PRIMA PARTE DEL PATH (ES "localhost:8080/KEY_CMD_REQ/date") 

#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 256
#endif

// COSTANTI DI ERRORE
#define GENERIC_INT_ERROR -1
#define GENERIC_NULL_ERROR NULL

// RITORNO PER encoding_xor_ip
#define FILE_EMPTY 11

// VALORI PER URI_TYPE
#define URI_IS_FILE 1                              // handle di un file
#define URI_IS_DIR 2                               // handle di una directory
#define URI_IS_CMD 3
#define URI_IS_INVALID_CMD 4
#define INVALID_URI 0

#ifdef _WIN32
// STRUTTURA UTILE PER LA CONDIVISIONE DI DATI TRA PROCESSI
struct share_params {
	char path_file_passwd[MAX_PATH_LEN];
    char pat_dir_file_log[MAX_PATH_LEN];
	short port_encyp;
	short port_plain;
	char pipe_name[MAX_PATH_LEN];
	char event_read_name[MAX_PATH_LEN];
	char name_file_log[MAX_PATH_LEN];
};

int get_unique_thread_id_string(char *buf);

void myWSAStartup();

#endif

typedef char *FILE_EXTENSION;

#ifndef _WIN32

/*
 *	Ritorna la lunghezza del file
 */
long get_file_size(FILE *stream);
#endif

/*
 *  Inizializzo mutex all'interno di questo modulo
 */
void init_utility_mutex();

/*
 *  Compila info con il valore del tempo di adesso.
 */
int get_local_time_now(struct tm *info_local);

/*
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Dato un uri o un unix path converte questo in un windows-path.
 * 
 *  @Return:
 *          -WIN_PATH
 *          -GENERIC_NULL_ERROR: Se occorso errore in concatenate_string
 */
WIN_PATH convert_uri_to_winpath(URI uri);

/*
 *     Stampa nello stderr: " <your string> : errno : <NAME_ERROR> "
 */
void print_my_error(char * stringErr);


void replace_token(char *str, size_t len_str, char tok, char sub);

/*
 *  Data una stringa str, fa una copia di essa in arr.
 *  Al termine arr sara una stringa.
 * 
 *  @Params:
 *          arr: puntatore ad array di lunghezza almeno len(str)+1
 *          str: stringa da copiare
 */
void copy_str_in_arr(char *str, char *arr);

/*
 *  Compara le str[da:a] e check, con da ed a inclusi.
 *  
 *  @Return:
 *          int: Il risultato di strcmp.
 */
int strcmp_da_a(char *str, char *check, int da, int a);


/*
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Restituisce un puntatore a una copia della sottostringa str(da,a), con da, a inclusi.
 *  La stringa ritornata contiene il terminatore di stringa '\0'
 *  Liberare la memoria puntata ritornata, spetta al chiamante.
 * 
 *  @Return:
 *          char *: puntatore alla sottostringa
 *          NULL : in caso di arrore con malloc
 */
char *strcpy_da_a(char *str, size_t da, size_t a);

/*
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Splitta la stringa passata in input, ogni volta che incontra 
 *  Liberare l'array all'interno della lista, spetta al chiamante.
 *      il token dato. Splitta automaticamente per "caratteri non stampabili".
 *  @Param:
 *          n_param: lunghezza array ritorno 
 *  @Return : 
 *          char **p: puntatore ad array di stringhe (ad array di puntatori char*)
 *          NULL: in caso di errore con malloc   
 */
list_t *split_by_token(char *str, size_t len, char token, char token_2);

/*
 *  Riceve in input una stringa e ne ritorna la posizione dell'ultimo newline '\n'
 *  @Return:
 *          >=0: posizione del '\n'
 *           -1: non trovato
 */
int find_last_newline(char *str, size_t len);

/*
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Prende un puntatore a buffer allocato dinamicamento o solo dichiarato
 *      e gli concatena una stringa.
 * 
 *  Nota2:(!!!!) Se il buffer non è stato prima allocato, buff deve puntare a NULL.
 *  Nota3: Il buffer puntato da point_to_buff e' sempre piu grande della stringa che contiene ;)   
 * 
 *  @Param:
 *          **point_to_buff: puntatore a puntatore al buffer allocato con malloc oppure NULL;
 *          *used_space: puntatore alla dimensione della memoria usata, ovvero la lunghezza della stringa in (**point_to_buff);
 *          *size_buff: puntatore alla dimensione totale del buffer in (**point_to_buff).
 *          *str: la stringa da appendere alla fine del buffer puntato da 'point_to_buff';
 *          len_str: len di str;
 *  @Return:
 *          0: se la concatenazione e' riuscita
 *         -1: se occorso errore in realloc
 */
int concatenate_string(char** point_to_buff, size_t *used_space, size_t *size_buff, char *str, size_t len_str);

/*  
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Concatena appende str2 a str1, ritorna un puntatore alla stringa str1_str2.
 *  Liberare la memoria puntata ritornata, spetta al chiamante.
 *  
 *  @Param:
 *          *str1: stringa alla quale appendere
 *          *str2: stringa da appendere
 */
char* my_strcat(char *str1, char *str2);

/*
 *  Dealloca la memoria puntata dagli elementi dell'array, ma non 
 *  la memoria allocata per l'array stesso.
 *  
 * @Param: 
 *      arr: array di cui si vuole deallocare la memoria;
 *      len: lunghezza dell'array
 */
void dealloc_array_of_char_pointer(void **arr, size_t len);

/*  
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Dato un URI verifica che esso sia uno tra:
 *      -FILE       --> URI_IS_FILE
 *      -DIRECTORY  --> URI_IS_DIR
 *      -NOT FOUND  --> INVALID_URI
 *	 -
 *  
 *  @Params:
 *          uri: l'uri da controllare     
 *        *path: puntatore a una variabile che conterra il path convertito da uri
 *  @Return:   
 *          -URI_TYPE;
 *          -GENERIC_INT_ERROR: Errore in convert_uri_path
 */
URI_TYPE get_uri_type(URI uri, PATH *path);

/*
 *  Controlla che l'uri-path sia una richiesta di comando, se si ritorna il nome di questo, 
 *  altrimenti torna null.
 *  Liberare memoria puntata ritornata, spetta al chiamante
 *  
 *  @Return:
 *          char *: Una stringa, ovvero il nome del comando nell'uri
 *          NULL:  se l'uri non è la richiesta di un comando.
 */
CMD is_command(URI uri);

/*
 *  Trasforma l'indirizzo ip in address in un intero senza segno e lo ritorna.
 */
unsigned int ip_to_uint(struct sockaddr *address);

/*
 *  Converte l'indirizzo ip fornito in formato stringa, nella notazione
 *  dotted.
 */
void ip_to_string(struct sockaddr *address, char *to_string);

void nport_to_string(struct sockaddr *address, char *to_string);

/*
 *  Copia i primi firsts byte di 'to_copy' in 'copy'.
 *  Si assume che 'copy' sia lungo almeno quanto 'to_copy'.
 */
void copy_arr(char *to_copy, size_t firsts, char *copy);

/*
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~
 *  Restituisce l'username, data una stringa del tipo "username:password"
 */
char *get_username(char *usr_psswd);

/*  
 *  ~~ RITORNA MEMORIA ALLOCATA SU HEAP ~~ 
 * 
 *  Codifica con il metodo dello XOR, utilizzando come seme ip.
 *  @Params:
 *          to_encode:  file da codificare
 *          len_to_enc: lunghezza di to_encode
 *          encoded:    file codificato
 *          len_encded: lunghezza encoded
 *          ip:         u_int indirizzo ip a 32bit letto come intero senza segno
 *  @Return:
 *          0:          Tutto ok
 *          GENERIC_INT_ERROR: errore
 */
int encoding_xor_ip(char **to_encode, size_t len_to_enc, char **encoded, size_t *len_encded, unsigned int ip);

void encoding_xor_ip_same_file(char **to_encode, size_t len_to_enc, unsigned int seed);

FILE_EXTENSION get_path_extension(PATH path);

#endif