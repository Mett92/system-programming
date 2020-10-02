/*
 *  manageConnection.h
 *  ServerApp
 *
 *  Created by Mattia Paolacci on 23/07/18.
 *  Copyright 2018 __MyCompanyName__. All rights reserved.
 *
 */
#ifndef _MANAGE_CONNECTION_H_
#define _MANAGE_CONNECTION_H_

#include "http_utility.h"
#include "functionality.h"

#define NULLPORT 0
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

typedef int socket_descriptor_t;

/*
 *	Inizializza il mutex per l'accept, questa funzione sarà chiamata dal 
 *  processo init.
 */
int init_accept_mutex();

/*
 *	Chiude/distrugge i mutex o i semafori aperti.
 */
void destroy_mutex_or_sem();

#ifdef _WIN32
/*
 *  Apre l'handle per il mutex già creato dal processo main.
 */
int init_accept_mutex_child_process(MODE flag_cyph);

#endif

/* 
 *	Prendi il mutex per l'accept
 */
int get_accept_mutex(MODE flag_cyph);

/*
 *	Rilascia mutex per l'accept
 */
int release_accept_mutex(MODE flag_cyph);

/* 
 *	Crea una socket e restiuisce il relativo socket descriptor.
 *	@Return: 
 *		> 0:            Socket Descriptor
 *		SOCKET_ERROR:   Se occorso errore;
 */
socket_descriptor_t get_socket_tcp();

/* 
 *	Assegna un numero di porta e un indirizzo IP(opzionale) alla socket in input
 */
int assign_address_to_socket(socket_descriptor_t socketDescriptor, int portno);

/*
 * Mette la socket in ascolto
 */
int take_socket_in_listen_status(socket_descriptor_t socketDescriptor, int maxRequest);

/*
 *	Mette la socket in accept (bloccante finche' non connesso al client).
 *  
 *  @Params: 
 *          addr:   indirizzo del client
 *      
 *	@Return:
 *			         >=0:	Il socket descriptor del client
 *			SOCKET_ERROR:	Se occorre un errore
 */
socket_descriptor_t take_socket_in_accept_status(socket_descriptor_t s, http_request_t *cl_req, MODE flag_cyph);

/*
 * Chiude la socket in input
 * Unix/Windows
 */
void my_close_socket(socket_descriptor_t s);

#endif