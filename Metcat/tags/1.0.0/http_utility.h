
#ifndef _HTTP_UTILITY_H_
#define _HTTP_UTILITY_H_

// INCLUDES
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "mime_type_utility.h"

// VARIABILI DI FUNZIONAMENTO                                                                                             // TITOLO PAGINA HTML DI OUTPUT
#define HTML_PAGE_NAME "OUTPUT"                     // TITOLO PAGINA HTML DI OUTPUT                     
#define HTTP_VER "HTTP/1.0"                         // HTTP VERSION

// TIPI DI VALORI PER UN HTTP-MESSAGE
typedef char *CONTENT_ENCODE;
typedef char *STATUS_CODE;  
typedef char *CONTENT_TYPE_PARAM;                   // Parametri in content-type di un http-msg
typedef char *HTTP_MESSAGE;                         // Messaggio HTTP 
typedef char *HTTP_REQUEST_METHOD;                  // Metodo di richiesta http: es PUT, GET...
typedef char *URI;                                  // Una stringa che rappresenta un URI

// VALORI PER HTTP_REQUEST_METHOD
#define HTTP_METH_GET "GET"
#define HTTP_METH_PUT "PUT"

// VALORI PER CONTENT_TYPE_PARAM
#define CHARSET_US_ASCII "charset=us-ascii"

// VALORI PER STATUS_CODE
#define CODE_200 "200 OK"
#define CODE_201 "201 Created"
#define CODE_500 "500 Internal Server Error"
#define CODE_403 "403 Forbidden"
#define CODE_401 "401 Unauthorized"
#define CODE_400 "400 Bad Request"


// STRUTTURA CHE CONTIENE I CAMPI DI INTERESSE DEL SISTEMA, DI UNA REQEUST HTTP
typedef struct http_request{
    struct sockaddr cl_addr;
    char *username;
    char *http_vers;
    HTTP_REQUEST_METHOD method;
    URI uri;
    char *authentication;
    char *body;
    size_t content_length;
}http_request_t;

// STRUTTURA CHE CONTIENE I CAMPI DI UNA RESPONSE HTTP
typedef struct http_response{
    char *status_code;
    char *status_line;
    char *content_encoding;
    char *content_length;                               // lunghezza di body
    size_t content_length_uint;
    char *content_type;                                 // tipicamente "text/html"
    char *body;
    size_t len_status_line;
    size_t len_content_encoding;
    size_t len_content_length;
    size_t len_content_type;
    size_t len_body;
} http_response_t;                                             

/*
 *  Inizializza i campi di una http_response_t tutti a NULL
 */
void init_response(http_response_t *resp);

void init_request(http_request_t *req);

/*
 *  Trova la posizione (un intero) di inizio del corpo del messaggio HTTP msg.
 *  
 *  @Return:
 *          int>0: la posizione;
 *          0   : Posizione non trovata;
 */
int find_bodys_start(HTTP_MESSAGE msg, size_t len_msg);

/*
 *  Trova posizione in cui l'header finisce.
 *  
 *  @Return:
 *          int>0: la posizione;
 *          0   : Posizione non trovata;
 */
int find_end_header(HTTP_MESSAGE msg, size_t len_msg);

/*
 *  Setta il campo content_type a "type/subtype" e len_content_type di resp.
 *  Solo charset puo essere NULL.
 *  @Params:
 *          type_subtype: E' il mimetype(IANA) del contenuto di body. 
 *                  E' una stringa in formato mimetype: "type/subtype"
 *          charset: i parametri di content-type, può essere NULL.
 *          *resp: puntatore alla response che si sta costruendo.
 * 
 *  @Return:   
 *          -1: se occorso errore
 *           0: se tutto ok
 */
int set_content_type(MIMETYPE mimetype, CONTENT_TYPE_PARAM charset, http_response_t *resp);

/*
 *  Setta il campo body di resp a file.
 *  @Return:   
 *          -1: se occorso errore
 *           0: se tutto ok
 */
int set_body(char *msg, size_t len_msg, http_response_t *resp);

/*
 *  Setta il campo status_line e len_status_line di resp a code.
 *  
 *  @Return:   
 *          -1: se occorso errore
 *           0: se tutto ok
 */
int set_status_line(STATUS_CODE code, http_response_t *resp);

/*
 *  Setta il campo content_encoding e len_content_encoding di resp.
 * 
 *  @Return:   
 *          -1: se occorso errore
 *           0: se tutto ok
 */
int set_content_encoding(CONTENT_ENCODE encode, http_response_t *resp);

/*  
 *  !!! resp->body non deve essere NULL !!!   
 *  Setta il campo content_length a "len(resp->body)" 
 *     e len_content_length a len(resp->content_length) di resp.
 * 
 *  @Return: 
 *          -1: se occorso errore
 *           0: se tutto ok
 */
int set_content_length(http_response_t *resp);

/*
 *  Crea un messaggio HTTP completo, prendendo come valori dei suoi campi, i rispettivi
 *  valori in resp.
 *  
 *  @Return:
 *          0: se tutto ok
 *         -1: altrimenti
 */
int assemble_response(http_response_t *resp, size_t *len_http_msg, HTTP_MESSAGE *http_msg);

/*
 *  Libera la memoria di una http_request_t
 * 
 *  NOTA: Chiamare solo se le variabili dentro http_req sono state allocate TUTTE DINAMICAMENTE
 */
void free_http_request(http_request_t *req);

/*
 *  Assicurarsi che la response passata in input sia stata inizializzata, altrimenti
 *      si verificano errori in free.
 */
void free_http_response(http_response_t *resp);

#endif