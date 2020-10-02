/*
 *  manageConnection.c
 *  ServerApp
 *
 *  Created by Mattia Paolacci on 23/07/18.
 *  Copyright 2018 __MyCompanyName__. All rights reserved.
 *
 */
#ifndef _WIN32
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <unistd.h>
	#include <pthread.h>
	#include <sys/sem.h>
	#include <sys/types.h>
	#include <sys/ipc.h>
	#include <sys/sem.h>
	#include <fcntl.h>
	#include <stdlib.h>
	#include <sys/mman.h>
#else
	#include <process.h>
	#include <winsock2.h>
	#include <windows.h> // da togliere
#endif

#include <stdio.h>
#include <stdlib.h>

// Files Project
#include "manage_connection.h"
#include "utility.h"
#include "manage_configuration.h"

extern struct config conf;

#ifndef _WIN32

// VALORI PER LA POSIZIONE DEL SEMAFORO NEL SET
#define SEMNUM_PLAIN 0
#define SEMNUM_ENC 1

// SET DI SEMAFORI PER L'ACCEPT
int id_set_sem;		
pthread_mutex_t mux_acpt_enc;
pthread_mutex_t mux_acpt_plain;

#else

// NOME DEL MUTEX PER L'ACCEPT
#define MUX_ACPT_NAME_PLAIN "mutex_acpt_plain"
#define MUX_ACPT_NAME_ENC "mutex_acpt_enc"

// HANDLE DEI MUTEX PER L'ACCEPT
HANDLE mux_acpt_plain = NULL;
HANDLE mux_acpt_enc = NULL;									
#endif

#ifdef _WIN32
void myWSAStartup(){
	WSADATA wsaData;
	int iResult;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2),&wsaData);
	if (iResult != 0) {
    	print_my_error("WSAStartup Failed!");
		WSACleanup();
	}
}
#endif

void destroy_mutex_or_sem(){
#ifndef _WIN32 
	if(conf.C_MODE_THREAD){
		pthread_mutex_destroy(&mux_acpt_plain);
		if (conf.C_PROCS_THREAD_ENCI) {
			pthread_mutex_destroy(&mux_acpt_enc);
		}
	}
	else{
		semctl(id_set_sem, 0, IPC_RMID);
	}
#else
	CloseHandle(mux_acpt_plain);
	if(conf.C_PROCS_THREAD_ENCI)
		CloseHandle(mux_acpt_enc);
#endif
}

// chiamata dal processo main
int init_accept_mutex(){
	int res = 0;	
	
	#ifndef _WIN32
	// CREO DUE SEMAFORI UNO PER LA ENCIFER E UN PER LA PLAIN PORT, PERMESSI 
	if(conf.C_MODE_PROCESS){
		int semflag =  IPC_CREAT | SEM_A | (SEM_A>>6);
		if ( (id_set_sem = semget(IPC_PRIVATE, conf.C_PROCS_THREAD_ENCI ? 2 : 1 , semflag)) == -1) {
			print_my_error("manage_connection.init_accept_mutex.semget");
			return -1;
		}
		
		// DEFINISCO LA UNION PER CREARE UN SEMAFORO BINARIO
		union semun args;
		args.val = 1;
		
		if(semctl(id_set_sem, SEMNUM_PLAIN, SETVAL, args)){
			print_my_error("manage_connection.init_accept_mutex.semctl");
			return -1;
		}
		
		if (conf.C_PROCS_THREAD_ENCI) {
			if(semctl(id_set_sem, SEMNUM_ENC, SETVAL, args)){
				print_my_error("manage_connection.init_accept_mutex.semctl");
				return -1;
			}
		}
	}
	else {
		res |= pthread_mutex_init(&mux_acpt_plain, NULL);
		if(conf.C_PROCS_THREAD_ENCI)
			res |= pthread_mutex_init(&mux_acpt_enc, NULL);
	}
	if(res) 
		print_my_error("manage_connection.pthread_mutex_init");


	#else
	// WINDOWS---------
	
	// CHIUDO GLI HANDLE DEI MUTEX IN CASO CHIAMASSI QUESTA FUNZIONE DOPO CTRL + C
	if(mux_acpt_enc != NULL)
		CloseHandle(mux_acpt_enc);
	if(mux_acpt_plain != NULL)
		CloseHandle(mux_acpt_plain);

	mux_acpt_plain = CreateMutexA(NULL, FALSE, MUX_ACPT_NAME_PLAIN);
	if(mux_acpt_plain == NULL){
		print_my_error("manage_connection.init_accept_mutex.CreateMutex.PLAIN");
		res = GENERIC_INT_ERROR;
	}
	if(conf.C_PROCS_THREAD_ENCI){
		mux_acpt_enc = CreateMutexA(NULL, FALSE, MUX_ACPT_NAME_ENC);
		if(mux_acpt_enc == NULL){
			print_my_error("manage_connection.init_accept_mutex.CreateMutex.ENCYPHER");
			res = GENERIC_INT_ERROR;
		}
	}

	#endif
	
	return res;
}

#ifdef _WIN32
int init_accept_mutex_child_process(MODE flag_cyph){
	if(flag_cyph){
		if( (mux_acpt_enc = CreateMutexA(NULL, FALSE, MUX_ACPT_NAME_ENC)) == NULL){
			print_my_error("manage_connectio.init_accept_mutex_child_process.CreateMutexA");
			return -1;
		}
	}
	else{
		if( (mux_acpt_plain = CreateMutexA(NULL, FALSE, MUX_ACPT_NAME_PLAIN)) == NULL){
			print_my_error("manage_connectio.init_accept_mutex_child_process.CreateMutexA");
			return -1;
		}
	}	
	return 0;
}
#endif

// CHIAMATA SOLO DAI CHILD PROCESS, SU WIN
int get_accept_mutex(MODE flag_cyph){
#ifdef _WIN32
	if(WaitForSingleObject(flag_cyph ? mux_acpt_enc : mux_acpt_plain, INFINITE) == WAIT_FAILED){
		print_my_error("manage_connection.get_accept_mutex.WaitForSingleObject");
		return GENERIC_INT_ERROR;
	}
	return 0;
#else
	if(conf.C_MODE_PROCESS){
		struct sembuf oper_get = { flag_cyph ? SEMNUM_ENC : SEMNUM_PLAIN, -1, 0};
		return semop(id_set_sem, &oper_get, 1);
	}
	else {
		return pthread_mutex_lock(flag_cyph ? &mux_acpt_enc : &mux_acpt_plain);
	}

#endif
}

int release_accept_mutex(MODE flag_cyph){
#ifdef _WIN32
	if(!ReleaseMutex(flag_cyph ? mux_acpt_enc : mux_acpt_plain)){
		print_my_error("manage_connection.release_accept_mutex.ReleaseMutex");
		return GENERIC_INT_ERROR;
	}
	
	return 0;
#else
	if(conf.C_MODE_PROCESS){
		struct sembuf oper_get = { flag_cyph ? SEMNUM_ENC : SEMNUM_PLAIN, 1, 0};
		return semop(id_set_sem, &oper_get, 1);
	}
	else {
		return pthread_mutex_unlock(flag_cyph ? &mux_acpt_enc : &mux_acpt_plain);
	}

#endif
}

socket_descriptor_t get_socket_tcp(){
	// Attiva/disattiva l'opzione in Sockopt
	int enable = 1;	
	int socketDescriptor;
	
	#ifdef _WIN32
		socketDescriptor = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	#else
	socketDescriptor = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

	#endif

	if(socketDescriptor < 0){
		print_my_error("manageConnection.getSocketTcp.socket");
		return GENERIC_INT_ERROR;
	}
	else {
		if(setsockopt(socketDescriptor, SOL_SOCKET, SO_REUSEADDR,(char *) &enable,sizeof(int))){
			print_my_error("manageConnection.getSocketTcp.setsockopt");
			return GENERIC_INT_ERROR;
		}
	}

	
	return socketDescriptor;
}

int assign_address_to_socket(socket_descriptor_t socketDescriptor, int portno){	
	// create address struct
	struct sockaddr_in server_addr;
	server_addr.sin_family = PF_INET;					//	Address family
	server_addr.sin_port = htons(portno);				//	Port number
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);	//	IP qualsiasi della macchina
	if (bind(socketDescriptor,(struct sockaddr *)&server_addr,sizeof(struct sockaddr_in)) < 0){
		print_my_error("manageConnection.assignAddressToSocket.bind");
		return -1;
	}
	return 0;
}

int take_socket_in_listen_status(socket_descriptor_t socketDescriptor, int maxRequests){
	if (listen(socketDescriptor, maxRequests)<0){
		print_my_error("manageConnection.takeSocketInlistenStatus.listen");
		return -1;
	}
	return 0;
}

socket_descriptor_t take_socket_in_accept_status(socket_descriptor_t s, http_request_t *cl_req, MODE flag_cyph){
	unsigned int len_sockaddr = sizeof(struct sockaddr);
	socket_descriptor_t client;
	
	// PRENDO IL MUTEX
	if(get_accept_mutex(flag_cyph)){
		print_my_error("manageConnection.take_socket_in_accept_status.get_accept_mutex");
		return SOCKET_ERROR;
	}
	
	client = accept(s, &(cl_req->cl_addr),
					#ifdef _WIN32
								(int *)
					#endif
								&len_sockaddr);
	
	// RILASCIO MUTEX
	if(release_accept_mutex(flag_cyph)){
		print_my_error("manageConnection.take_socket_in_accept_status.release_accept_mutex");
		return SOCKET_ERROR;
	}

	if (client<0) {
		print_my_error("manageConnection.takeSocketInAcceptStatus.accept");
		return SOCKET_ERROR;
	}
	else 
		return client;
	
}

void my_close_socket(socket_descriptor_t s){
	#ifdef _WIN32
		closesocket(s);
	#else 
		close(s);
	#endif
}