
#ifndef _FUNCTIONALITY_H_
#define _FUNCTIONALITY_H_



#include "http_utility.h"
#include "utility.h"

#define CYPH 1                                // ritorna il corpo cifrato con lo xor
#define NOT_CYPH 0

typedef int MODE;

#ifdef _WIN32
DWORD WINAPI execute_command_thread(LPVOID params);

#else
int execute_command_thread(void *arg);

#endif

/*
 *  Esegue il comando (bash o cmd) "name", ritornado un puntatore all'output generato.
 *  Liberare la memoria puntata ritornata spetta al chiamante.
 *  @Params:
 *          cmd_name: nome del comando bash/prompt da eseguire
 *          *output_len: puntatore alla variabile che conterrà la lunghezza dell'output
 *  @Return:
 *          NULL: se occorso errore
 *          *char: puntatore al buffer contenente l'output del comando richiesto   
 */ 
char *execute_command(CMD cmd_name, size_t *output_len);

/*
 *  Gestisce una richiesta HTTP, incapsulando il risultato nella response HTTP.
 *  @Params:
 *		request: Puntatore a struttura http_request_t, ovvero la richiesta HTTP del client.
 *		response: Puntatore a struttura http_response_t, corrisponde alla risposta HTTP al client.
 *		m: scegliere tra CYPH oppure 0;
 *		seed: rappresenta il seme della codifica in xor se m diverso da zero, altrimenti non viene considerato.
 *  @Return: 
 *          0: Se tutto ok.
 *          GENERIC_INT_ERROR: Se occorso errore
 *          
 */
int manage_http_request(http_request_t *request, http_response_t *resp, MODE m, unsigned int seed);

int manage_get_method(http_request_t *request, http_response_t *resp, MODE m, unsigned int seed);

int manage_put_method(http_request_t *request, http_response_t *resp);

/*
 *	Apre il file "name_file" e inizializza response passata in input. 
 *	@Params:
 *			name_file: nome del file, con il path intero, da ritornare
 *			resp: response da spedire al client
 *			m: scegliere tra CYPH oppure 0;
 *			seed: rappresenta il seme della codifica in xor se m diverso da zero, altrimenti non viene considerato.
 *	@Return:
 * 			0: OK
 *			generic_int_error: Errore
 */
int get_response_file(PATH name_file, http_response_t *resp, MODE m, unsigned int seed);

/*
 *  Esegue il comando 'cmd_name' e incapsula il risultato nella response.
 *  NOTA:
 *      Imposta i seguenti campi dell'HTTP-response:
 *          -Status-line;
 *          -Content-type
 *          -Body
 * 
 *  @Return:
 *          0: OK
 *         -1: GENERIC_INT_ERROR
 */
int get_response_command(CMD cmd_name, http_response_t *resp);

#endif 