/*
 *	moduleHttp.h file
 *	Created by Mattia Paolacci
 * 
 */

#ifndef _MANAGE_AUTHENTICATION_H_
#define _MANAGE_AUTHENTICATION_H_


#include <stdlib.h>
#include "manage_connection.h"
#include "http_utility.h"

// FUNZIONI

/*
 *  Inizializza la http_request_t il body incluso nel messaggio http di richista.
 *  
 *  NOTA: Chiamare solo se il body e' presente.
 * 
 *  @Return:
 *          0                   : tutto ok
 *          generic_int_error   : errore.
 * 
 */
int get_body_recv(socket_descriptor_t cl, http_request_t *req, HTTP_MESSAGE *msg, size_t *len_msg, size_t *sp_alloc);

/*
 *  Inizializza i campi dell'header della http_request_t, con i valori dell'header nel messaggio HTTP di richiesta.
 *  Se ritorna errore, la request data in input, sara re-inizializzata con init_request.
 *  
 *  @Return:
 *          0                   : tutto ok
 *          generic_int_error   : errore.
 */
int get_header_recv(socket_descriptor_t cl, http_request_t *req, HTTP_MESSAGE *msg, size_t *len_msg, size_t *space_allocated);

/*	
 *	Inizializza la request passata e setta i valori corrisponenti a quelli 
 *		nell'header del messaggio HTTP.
 *
 *  @Return:
 *          0                   : tutto ok
 *          generic_int_error   : Se occorso errore in sscanf per content-length
 */
int get_params_header(http_request_t *req, HTTP_MESSAGE msg, size_t end_header);

/* 
 *  Prende in inputa la request in formato stringa, splitta il testo per spazi, ed estra i parametri di 
 *  interesse.
 *  @Params:
 *          client_request: puntatore alla request
 *          dim: dimensione di client_request
 * 
 *  NOTA: Liberare la memoria ritornata spetta al chiamante.
 */
http_request_t get_params(char *client_request, size_t dim);
/*
 *  1)Server accetta connessione del client cl:
 *      -se questo invia http-request con credenziali allora vai al punto 1A), altriemnti al punto 2A).
 *      1A)Se questo ha le credenziali registrate, authenticated_client ritorna il socket_descriptor_t di cl
 *           altrimenti va al punto 2A).
 *      2A)Invia al client HTTP-response con richiesta di base authentication e torna al punto 1).
 *  
 *  NOTA: cl_addr e len_cl_addr possono essere NULL.
 *  
 *  @Return: 
 *      http_request_t di un Client che si e' autenticato ed e' in attesa di una HTTP-Response.
 * 
 *  NOTA:   Chiudere il socket_descriptor_t del client ritornato spetta al chiamante.
 *  NOTA2:  Liberare memoria "client_socket" spetta al chiamante.
 */
void authenticated_client(socket_descriptor_t server_socket, socket_descriptor_t *cl, http_request_t *req_cl, MODE flag_cyph);

/*
 *  Prende in input le credenziali codificate in base64, le decodifica e controlla
 *      se presenti nel DB.
 *  @Return:
 *          1: se credenziali trovate
 *          0: se non trovate
 *         -1: se occorso errore    
 */
int check_credentials(char *usrpasswd_encd, size_t len, http_request_t *cl_req);

#endif