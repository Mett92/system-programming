#include <string.h>
#include <stdio.h>

#ifdef _WIN32
	#include <windows.h>
#else
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <sys/uio.h>
	#include <unistd.h>
#endif

// Project files
#include "manage_authentication.h"
#include "utility.h"
#include "list.h"
#include "b_64.h"
#include "log4c.h"
#include "http_utility.h"
#include "manage_configuration.h"

// RISPOSTE DA INVIARE AL CLIENT RISP. IN CASO DI ERRORE INTERNO/RICHIESTA AUTENTICAZIONE
#define MSG_ERROR_500 "HTTP/1.0 500 Internal Server Error\r\n\r\nERRORE INTERNO."
#define MSG_REQUEST_AUTH "HTTP/1.0 401 Access Denied\r\nWWW-Authenticate: Basic realm=\"Autenticati al server\"\r\n\r\nCREDENZIALI ERRATE OPPURE NON AUTENTICATO!"
#define UNK_USR "unknow-user"

// LUNGHEZZA MASSIMA PASSWORD E USERNAME
#define PASSWD_MAX_LEN 10
#define USERN_MAX_LEN 20

//	BUFFER PER LA RECV
#define RECV_BUFFER_SIZE 64		

// CONFIGURAZIONE DEL PROGRAMMA
extern struct config conf;

/*
 *	Funzione generica UW
 */
int get_body_recv(socket_descriptor_t cl, http_request_t *req, HTTP_MESSAGE *msg, size_t *len_msg, size_t *sp_alloc){	
	int tot_b_recved = 0;																						// byte totali ricevuti
	int bRec = 0;
	char recv_buff[RECV_BUFFER_SIZE];
	int start_body = find_bodys_start(*msg, *len_msg);
	size_t body_partial = *len_msg - start_body;																// parte del body gia ricevuto
	int byte_to_recv = (int)req->content_length - (int)body_partial;												// parte rimanente del body da ricevere

	while(byte_to_recv > tot_b_recved){
		bRec = recv(cl, recv_buff, RECV_BUFFER_SIZE,0);
		
		//	SE TUTTO OK
		if(bRec > 0){
			if(concatenate_string(msg, len_msg, sp_alloc, recv_buff, bRec)){
				print_my_error("manage_authentication.get_body_recv.concatenate_string");
				return GENERIC_INT_ERROR;
			}
			else
				tot_b_recved += bRec;
		}
		
		//	ERRORE SOCKET
		else if(bRec == SOCKET_ERROR){
			print_my_error("manage_authentication.get_body_recv.recv");
			return GENERIC_INT_ERROR;
		}	
		
		// CHIUSURA INATTESA CONNESSIONE
		else if(bRec == 0){
			print_my_error("manage_authentication.get_body_recv.CLOSED_CONNECTION_UNEXPECTEDLY_BY_CLIENT");
			return GENERIC_INT_ERROR;
		}
	
	}
	
	// LA CONTENT-LENGTH INVIATA DAL CLIENT NON CORRISPONDE ALLA LUNGHEZZA DEL BODY
	if(byte_to_recv<0){
		print_my_error("manage_authentication.get_body_recv.INVALID_CONTENT_LENGTH_SEND_BY_CLIENT");
		return GENERIC_INT_ERROR;
	}

	size_t end_body = ((size_t)start_body) + req->content_length;
	req->body = strcpy_da_a(*msg, (size_t)start_body, end_body);
	
	if(req->body != NULL)
		return 0;
	else{
		print_my_error("manage_authentication.get_body_recv.strcpy_da_a");
		return GENERIC_INT_ERROR;
	}
}

/*
 *	Funzione generica UW
 */
int get_header_recv(socket_descriptor_t cl, http_request_t *req, HTTP_MESSAGE *msg, size_t *len_msg, size_t *space_allocated){
	int bRec = 0;
	char recv_buff[RECV_BUFFER_SIZE];
	int end_head = 0;																				//	dove termina l'header
	
	do{
		bRec = recv(cl, recv_buff, RECV_BUFFER_SIZE,0);
		
		//	SE TUTTO OK
		if(bRec > 0){	
			if(concatenate_string(msg, len_msg, space_allocated, recv_buff, bRec)){
				print_my_error("manage_authentication.get_header_recv.concatenate_string");
				return GENERIC_INT_ERROR;
			}
		}
		//	ERRORE SOCKET
		else if(bRec == SOCKET_ERROR){
			print_my_error("manage_authentication.get_header_recv.SOCKET_ERROR");
			return GENERIC_INT_ERROR;
		}	
		// CHIUSURA INATTESA CONNESSIONE
		else if(bRec == 0){
			print_my_error("manage_authentication.get_header_recv.CLOSED_CONNECTION_UNEXPECTEDLY");
			return GENERIC_INT_ERROR;
		}	

		end_head = find_end_header(*msg, *len_msg);

	}while(!end_head);
	return get_params_header(req, *msg, end_head);
}

/*
 *	Funzione generica UW
 */
int get_params_header(http_request_t *req, HTTP_MESSAGE msg, size_t end_header){
	int res = 0;
	init_request(req);
	list_t *split_msg = split_by_token(msg, end_header, ' ','\n');									
	int aut = find_in_list(split_msg,"Authorization:");
	int indx_cnt_len = find_in_list(split_msg, "Content-Length:");
	
	// SETTO L'HEADER
	req->method = get_element_from_list(split_msg,0);
	req->uri = get_element_from_list(split_msg,1);
	req->http_vers = get_element_from_list(split_msg,2);		
	split_msg->array[0] = NULL;																		// 	Prima di liberare memoria allocata dinamicamente...
	split_msg->array[1] = NULL;																		// ...elimino riferimento ai dati di interesse, altrimenti questi... 
	split_msg->array[2] = NULL;																		// ...verranno persi in dealloc_array_of_char_pointer.

	// CONTROLLO CHE IL CLIENT ABBIA INVIATO CREDENZIALI AUTENTICAZIONE
	if(aut != ELEM_LIST_NOT_FOUND){
		req->authentication = get_element_from_list(split_msg,aut+2);	
		
		if(indx_cnt_len != ELEM_LIST_NOT_FOUND){
			size_t cnt_len;
			if (1 == sscanf(get_element_from_list(split_msg, indx_cnt_len+1), "%lu", &cnt_len))			//converto string in size_t
				req->content_length = cnt_len;
			else{
				print_my_error("manage_authentication.get_params_header.sscanf_CONTENT_LENGTH");
				res = GENERIC_INT_ERROR;
			}
		}
		split_msg->array[aut+2] = NULL;																	
	}
	dealloc_array_of_char_pointer((void**)split_msg->array, split_msg->len);
	destroy_list(split_msg);
	return res;	
}

/*
 *	Funzione generica UW
 */
void authenticated_client(socket_descriptor_t server_socket, socket_descriptor_t *cl, http_request_t *req_cl, MODE flag_cyph){   
	init_request(req_cl);																					// quando la funzione termina
	// LA FUNZIONE NON RITORNA FINCHE UN CLIENT NON SI AUTENTICA
	while(1){	
		// DICHIARAZIONE E DEFINIZIONE VARIABILI
		HTTP_MESSAGE msg = NULL;
		size_t len_msg = 0;
		size_t space_allocated = 0;
		
		// PER VERIFICARE ERRORI
		int res = 0;	

		// VARIABILI PER CLIENT DA AUTENTICARE
		http_request_t req_cl_aut;
		init_request(&req_cl_aut);																		// request del client da autenticare
		socket_descriptor_t cl_aut = take_socket_in_accept_status(server_socket, &req_cl_aut, flag_cyph);						// client da autheticare
		if(cl_aut == SOCKET_ERROR){
			print_my_error("manage_authentication.authenticated_client.take_socket_in_accept_status");
			continue;
		}
		
		// RICAVO HEADER DEL CL DA AUTENTICARE
		res = get_header_recv(cl_aut, &req_cl_aut, &msg, &len_msg, &space_allocated);	
		
		if(res)
			print_my_error("manage_authentication.authenticated_client.get_header_recv");

		// CONTROLLO SE LE CREDENZIALI SONO STATE FORNITE
		if( (req_cl_aut.authentication != NULL) && !res){		
			// VERIFICO LE CREDENZIALI
			res = check_credentials(req_cl_aut.authentication, strlen(req_cl_aut.authentication), &req_cl_aut);  
			
			if(res == GENERIC_INT_ERROR)	
				print_my_error("manage_authentication.authenticated_client.check_credentials");
			if(res == 1){
				res = 0; 																				
				
				// SE E' UNA PUT 
				if(strcmp(req_cl_aut.method,HTTP_METH_PUT) == 0){
					res = get_body_recv(cl_aut,&req_cl_aut,&msg,&len_msg,&space_allocated);			// erroe interno
					if(res)
						print_my_error("manage_authentication.authenticated_client.get_body_recv");
				}

				// SE RES = 0 ALLORA O NON ERA UNA PUT OPPURE NESSUN ERRORE IN GET_BODY
				if(!res){																				
					*cl = cl_aut;
					*req_cl = req_cl_aut; 
					free(msg);
					return;
				}
			}
		}
		free(msg);
		
		// SE OCCORSO ERRORE O NON AUTENTICATO
		free(req_cl_aut.username);
		req_cl_aut.username = strcpy_da_a(UNK_USR, 0, strlen(UNK_USR)-1);
		
		// INIZIALIZZO RESPONSE PER LOG
		http_response_t resp_log;
		init_response(&resp_log);
		
		// SE ERRORE INTERNO LO SEGNALO AL CLIENT E LOGGO
		if(res){
			set_status_line(CODE_500, &resp_log);
			resp_log.content_length_uint = strlen("ERRORE INTERNO.");
			append_common_log_format(&req_cl_aut, &resp_log, flag_cyph);
			send(cl_aut,MSG_ERROR_500, strlen(MSG_ERROR_500),0);
		}
		// ALTRIMENTI CREDENZIALI ASSENTI O ERRATE SEGNALO AL CLIENT E LOGGO
		else{
			set_status_line(CODE_401, &resp_log);
			resp_log.content_length_uint = strlen("CREDENZIALI ERRATE OPPURE NON AUTENTICATO!");
			append_common_log_format(&req_cl_aut, &resp_log, flag_cyph);
			send(cl_aut, MSG_REQUEST_AUTH, strlen(MSG_REQUEST_AUTH), 0);
		}
		
		free_http_request(&req_cl_aut);
		free_http_response(&resp_log);
		my_close_socket(cl_aut);
	}
}

/*
 *	Funzione promiscua
 */
int check_credentials(char *usrpssw_encd, size_t len, http_request_t *cl_req){
	// WINDOWS & UNIX
	size_t dec_len;
	unsigned char *str_decd = base64_decode(usrpssw_encd, len, &dec_len);								// Allocata con malloc

	if(str_decd == NULL){
		print_my_error("manage_authentication.check_credentials.base64_decode : FORMAT ERROR OF 'usrpssw_encd'");
		base64_cleanup();
		return -1;
	}
	base64_cleanup();
	char *usrpssw = strcpy_da_a((char*)str_decd,0,dec_len-1);
	cl_req->username = get_username(usrpssw);
	free(str_decd);
	
	// WINDOWS
	#ifdef _WIN32
	HANDLE file_passwd_handle = CreateFile(conf.C_PATH_PASSWD,GENERIC_READ,FILE_SHARE_READ,NULL,			// APRO FILE PASSWD
									OPEN_EXISTING,0,NULL); 							// FILE_SHARE_READ: consente ad altri processi di aprire il file in lettura
	if(file_passwd_handle == INVALID_HANDLE_VALUE){														// Controllo se open andata bene
		print_my_error("manage_authentication.check_credentials.CreateFile");
		return -1;
	}
	DWORD byte_read;																					// numero di byte letti all'i-esimo ciclo
	
	// UNIX
	#else
	ssize_t byte_read;																					// numero di byte letti all'i-esimo ciclo
	int file_passwd = open(conf.C_PATH_PASSWD, O_RDONLY);														// Open file passwd
	if(file_passwd == -1){
		print_my_error("manage_authentication.check_credentials.open");
		return -1;
	}
	#endif
	
	// WINDOWS & UNIX
	int len_buff = (USERN_MAX_LEN + PASSWD_MAX_LEN)*1 + 1;												// Ovvero deve contenere almeno la somma della massima lunghezza di usr e pass; +1 per il carattere '\n' nel caso find_last_newline restituisca -1
	char read_buff[len_buff];																			
	int last_newln;																						// ultimo new line 
	list_t *list_users;																					// lista di usr:passw
	int start_byte = 0; 																				// da dove i-esimo ciclo iniziera a leggere il file passwd
	do{
		// WINDOWS
		#ifdef _WIN32
		if(!ReadFile(file_passwd_handle,read_buff,len_buff,&byte_read,NULL)){
			print_my_error("manage_authentication.check_credentials.ReadFile");
			CloseHandle(file_passwd_handle);
			return -1;
		}
		
		// UNIX
		#else
		byte_read = read(file_passwd, read_buff, len_buff);
		if (byte_read == -1) {
			print_my_error("manage_authentication.check_credentials.ReadFile");
			close(file_passwd);
			return -1;
		}
		#endif

		// WINDOWS & UNIX
		last_newln = find_last_newline(read_buff,(size_t)byte_read);									// trova l'ultima occorrenza di '\n'
		start_byte = start_byte + last_newln + 1;														// al prossimo ciclo legge dalla posizione successiva all'ultimo '\n'
		
		// WINDOWS
		#ifdef _WIN32
		SetFilePointer(file_passwd_handle,(LONG)start_byte,NULL,FILE_BEGIN);							// imposta il puntatore per il prossimo ciclo
		
		// UNIX
		#else
		lseek(file_passwd, start_byte, SEEK_SET);														// Posiziono il puntatore di lettura, con SEEK_SET il puntatore viene impostato a 'inizio_file' + 'start_byte'  
		#endif
		
		// WINDOWS & UNIX
		if(last_newln==-1){																				// Se sono all'ultima riga e'\n' non e' presente aggiungilo nel buffer
			read_buff[byte_read] = '\n';	
			list_users = split_by_token(read_buff,byte_read,'\n',' ');				
		}
		else			
			list_users = split_by_token(read_buff,last_newln,'\n',' ');		

		int i = find_in_list(list_users,usrpssw);														// cerco se nella lista c'e' usr:pssw
		if(i>=0){																						// se c'e' ritorna 1
			dealloc_array_of_char_pointer((void**)list_users->array,list_users->len);
			destroy_list(list_users);																	// DEALLOCO tutto
			free(usrpssw);
			#ifdef _WIN32
			CloseHandle(file_passwd_handle);
			#else
			close(file_passwd);
			#endif
			return 1;
		}
		dealloc_array_of_char_pointer((void**)list_users->array,list_users->len);
		destroy_list(list_users);
	}while((byte_read > 0) && (last_newln>=0));															// Continua a leggere finche i byte letti non sono pari a 0 e sei dentro il file
	
	// WINDOWS
	#ifdef _WIN32
	if(!CloseHandle(file_passwd_handle)){
		print_my_error("manage_authentication.check_credentials.CloseHandle");
	}
	
	// UNIX
	#else
	if(close(file_passwd) == -1){
		print_my_error("manage_authentication.check_credentials.CloseHandle");
	}
	#endif
	// WINDOWS & UNIX
	free(usrpssw);
	
	return 0;
}
