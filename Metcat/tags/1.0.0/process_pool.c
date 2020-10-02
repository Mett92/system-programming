/*
 *  Questo modulo viene usato per i processi all'interno del Pool del server, in caso
 *  quest'ultimo venisse avviato in modalità Multi-process.
 *  
 *  Created By 
 *  Mattia Paolacci
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "manage_authentication.h"
#include "utility.h"
#include "functionality.h"
#include "http_utility.h"
#include "manage_configuration.h"
#include "log4c.h"

// DICHIARAZIONE FUNZIONI
void task();
int set_console_handler();

// VARIABILI GLOBALI
SOCKET serverSocket;
MODE flag_cyph;									// modalità del processo, ovvero se è un processo che ritorna il file cifrato o meno
struct config conf;
extern char name_file_log[];
BOOL event_kill = FALSE;						// questo flag indica che il processo ha ricevuto CTRL+C o CTRL+BREAK, quindi il processo event_kill non appena finisce il task.
BOOL task_complete = TRUE;						// indica che il processo ha completato il task, quindi richiamato la funzione send per rispondere al client.

CRITICAL_SECTION cs_event_kill;					//	
CRITICAL_SECTION cs_task_complete;				//	implementano le sezioni critiche per le variabili che hanno rispettivo nome descritto dopo cs_..

// processo nel pool, argv[1] è il nome della memoria condivisa per il lock
// sulla funzione accept
int main(int argc, char const *argv[])
{  
	// INIZIALIZZO LE SEZIONI CRITICHE
	InitializeCriticalSection(&cs_event_kill);
	InitializeCriticalSection(&cs_task_complete);
	
	// MUTEX PER LOCAL TIME
	init_utility_mutex();

	// SETTO IL CONTROL HANDLER 
	if(set_console_handler()){
		print_my_error("process_pool.set_console_handler");
		return 1;
	}
	
	// CONTROLLO CHE SIA STATO FORNITO IL NOME PER IL MEMORY MAP
	if(argc < 2){
		print_my_error("process_pool.ARGOMENTI_MANCANTI");
		return 1;
	}

	// IMPOSTO MODALITA DI RITORNO (CIFRATA--> 0 OPPURE IN CHIARO-->1)
	flag_cyph = atoi(argv[1]);

	// APRO MUTEX PER L'ACCEPT
	init_accept_mutex_child_process(flag_cyph);
	
    // APRO LA MMAP E LA VIEW
    HANDLE mem_shr = OpenFileMappingA(FILE_MAP_READ, FALSE, argv[0]);
    struct share_params *pt_shr_par = (struct share_params *) 
                                MapViewOfFile(mem_shr, FILE_MAP_READ, 0, 0, sizeof(struct share_params));
	
    // COPIO I PARAMETRI DALLA MEMORIA CONDIVISA IN LOCALE
    conf.C_DIR_FILE_LOG = strcpy_da_a(pt_shr_par->pat_dir_file_log, 0, strlen(pt_shr_par->pat_dir_file_log)-1); 
    conf.C_PATH_PASSWD = strcpy_da_a(pt_shr_par->path_file_passwd, 0 , strlen(pt_shr_par->path_file_passwd)-1);	
	conf.C_PORT_PLAIN = pt_shr_par->port_plain;
	conf.C_PORT_ENCIPHER = pt_shr_par->port_encyp;
	char *pipe_name = strcpy_da_a(pt_shr_par->pipe_name, 0, strlen(pt_shr_par->pipe_name));						// deallocare
	char *event_read_name = strcpy_da_a(pt_shr_par->event_read_name, 0, strlen(pt_shr_par->event_read_name)-1); // deallocare
	strcpy(name_file_log, pt_shr_par->name_file_log);

	// CHIUDO LA VIEW ED HANDLE DELLA MAP
	UnmapViewOfFile(pt_shr_par);
	CloseHandle(mem_shr);

	// APRO EVENTO PER LA SYNC CON IL PROCESSO INIT
	HANDLE event_read = OpenEventA(EVENT_MODIFY_STATE, FALSE, event_read_name);
	if(event_read == INVALID_HANDLE_VALUE){
		print_my_error("processo_win.OpenEventA");
		return 1;
	}

	// APRO LA PIPE PER RICEZIONE DATI DAL PROCESSO MAIN
	HANDLE pipe;
	if( (pipe = CreateFileA(pipe_name, GENERIC_READ|FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE){
		print_my_error("server.crea_pool_processi.CreateFileA.APERTURA_PIPE");
		return 1;
	}

	// CONFIGURO PIPE PER LA LETTURA
	DWORD mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
	if(!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)){
		print_my_error("server.crea_pool_processi.SetNamedPipeHandleState");
		return 1;
	}

	// LEGGO DATI DALLA PIPE
	size_t len_buff = sizeof(WSAPROTOCOL_INFO);
	char buffer[len_buff];
	DWORD byte_read;
	ReadFile(pipe, buffer, len_buff, &byte_read, NULL);

	// SEGNALO AL MAIN PROCESS L'AVVENUTA LETTURA
	SetEvent(event_read);

	// CHIUDO GLI HANDLE
	CloseHandle(pipe);
	CloseHandle(event_read);

	// INIZIALIZZO VARIABILE WSAPROTOCOL_INFO
	WSAPROTOCOL_INFO *wsa_proto = (WSAPROTOCOL_INFO *)buffer;
	
	// ABILITO SOCKET
	myWSAStartup();
	serverSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,wsa_proto, 0,0);

	// DEALLOCO MEMORIA
	free(pipe_name);
	free(event_read_name);

	// AVVIO TASK PROCESSO
    while(1){
		EnterCriticalSection(&cs_event_kill);
		if(event_kill){
			LeaveCriticalSection(&cs_event_kill);
			break;
		}
		LeaveCriticalSection(&cs_event_kill);
		task();
	}
    
	closesocket(serverSocket);
    return 0;
}


// task del server
void task(){
	
	// VARIABILI PER GESTIRE LA REQUEST DI UN CLIENT
	socket_descriptor_t cl;
	http_request_t req;

	// RIMANE IN ATTESA DI UN CLIENT AUTENTICATO
	authenticated_client(serverSocket, &cl, &req, flag_cyph);

	// DICHIARO TASK NON COMPLETATO
	EnterCriticalSection(&cs_task_complete);
	task_complete = FALSE;
	LeaveCriticalSection(&cs_task_complete);
	
	// CREO RESPONSE E LA INZIALIZZO
	http_response_t resp;
	init_response(&resp);
	
	// MESSAGGIO HTTP DI RISPOSTA
	HTTP_MESSAGE msg;
	size_t len_msg;
	
	// GESTISCO REQUEST
	if(!manage_http_request(&req, &resp, flag_cyph, ip_to_uint(&req.cl_addr))){
		set_content_type(TEXT_PLAIN, NULL, &resp);
		set_content_length(&resp);
	}
	else{
		char err_msg[] = "ERRORE INTERNO!";
		set_status_line(CODE_500, &resp);
		set_body(err_msg, strlen(err_msg), &resp);
	}
	append_common_log_format(&req, &resp, flag_cyph);
	assemble_response(&resp, &len_msg, &msg);
	
	// SPEDISCO MESSAGGIO
	send(cl, msg, len_msg, 0);
	shutdown(cl, SD_SEND);
	my_close_socket(cl);
	
	// LIBERO RISORSE
	free(msg);
	
	free_http_response(&resp);
	free_http_request(&req);
	
	// DICHIARO TASK COMPLETATO
	EnterCriticalSection(&cs_task_complete);
	task_complete = TRUE;
	LeaveCriticalSection(&cs_task_complete);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType){
	if(fdwCtrlType == CTRL_C_EVENT){
		BOOL term = FALSE;
		EnterCriticalSection(&cs_event_kill);
		EnterCriticalSection(&cs_task_complete);
		
		//	SE IL TASK E' SEGNALO FLAG TERMINAZIONE IMMMEDIATA
		if(task_complete)
			term = TRUE;

		// TERMINAZIONE POSTICIPATA ALLA FINE DEL TASK
		else
			event_kill = TRUE;
	
		LeaveCriticalSection(&cs_event_kill);
		LeaveCriticalSection(&cs_task_complete);
		
		if(term){
			destroy_mutex_or_sem();
			ExitProcess(EXIT_SUCCESS);
		}
		return TRUE;
	}
	else
		return FALSE;
}

int set_console_handler(){
	//	IMPOSTO GLI HANDLER PER EVENTI CONSOLE
	if(!SetConsoleCtrlHandler(CtrlHandler, TRUE)){
		print_my_error("utility.set_console_handler.FAILED_CREATING_CONSOLE_CONTROL_HANDLER");
		return GENERIC_INT_ERROR;
	}

	return 0;
}
