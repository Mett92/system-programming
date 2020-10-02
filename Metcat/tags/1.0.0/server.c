/*
 *	Main file of Server
 *	Created by Mattia Paolacci
 */

#ifdef _WIN32	
#include <windows.h>
#include <direct.h>
#define CHILD_PROC_NAME "\\process_pool.exe"
#define MAIN_PROC_NAME "\\Metcat.exe"
#define MEM_PROC_SHRD_NAME "Global\\memoryProcessShared"
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#endif
#include <stdio.h>
#include <string.h>

// File project
#include "manage_authentication.h"
#include "utility.h"
#include "functionality.h"
#include "http_utility.h"
#include "manage_configuration.h"
#include "server.h"
#include "log4c.h"

// VARIABILI GLOBALI
struct config conf; 
params_main_t params;
socket_descriptor_t serverSocket;
socket_descriptor_t serverSocket_enc;		// socket per la cifratura
extern char name_file_log[];

#ifdef _WIN32
PROCESS_INFORMATION *procs_arr_plain = NULL;	// array degli handle dei processi in chiaro;
PROCESS_INFORMATION *procs_arr_enc = NULL;
HANDLE *thread_arr_enc = NULL;
HANDLE *thread_arr_plain = NULL;
HANDLE event_keyboard;										// evento per CTRL+C

// GLOBAL-VAR PER MULTI-THREAD
HANDLE event_autokill_thread = NULL;						//  quando segnalato il thread si autokilla da solo. evento di tipo manual rest.	
HANDLE event_not_busy = NULL;								//  quando segnalato indica che nessun thread e' occupato
HANDLE mux_nBusy = NULL;									// 	mutex per la variabile nBusy
int nBusy = 0;												// 	contatore che indica il numero di thread occupati
#endif

#ifndef _WIN32
pthread_cond_t event_keyboard  = PTHREAD_COND_INITIALIZER;			
pthread_mutex_t mux_event_keyboard = PTHREAD_MUTEX_INITIALIZER;
pthread_t *thread_arr_enc = NULL;
pthread_t *thread_arr_plain = NULL;
pid_t *procs_arr_plain = NULL;
pid_t *procs_arr_enc = NULL;
int last_signal = 0;												// indica che e' occorso un segnale quindi i thread devono terminare, 
pthread_key_t busy_key;													// indica se il thread e' impegnato in un job
int process_busy = 0;
#endif

int main(int argc, char** argv){
	
	#ifndef _WIN32
	if(deamonize())
		return 1;
	#endif
	
	// SETTO IL GESTORE DEI SEGNALI/EVENTI CONSOLE 
	if(set_console_handler()){
		print_my_error("server.set_console_handler");
		return 1;
	}
	
	#ifdef _WIN32
	// INIALIZZO MUTEX PER GET DEL LOCAL TIME  -
	init_utility_mutex();					
	#endif

	// PARAMETRI DEL MAIN DATI DALL'UTENTE
	init_config_struct(&conf);
	
	// CONTROLLO SE L'INPUT DEL PROGRAMMA SIA BEN FORMATO
	if(check_arguments(argc, argv))				
		return 1;		
	
	while(1){
		#ifdef _WIN32
		myWSAStartup();
		#endif

		// INIZIALIZZO STRUTTURA CONFIG
		if(get_configuration(&conf)){
			print_my_error("Errore di lettura nel file di configurazione.");
			return 1;
		}
		
		// CONTROLLO LA CONFIGURAZIONE
		if(check_configuration(&conf))
			return 1;
		print_my_error("Configurazione completata.");

		// INIZIALIZZO MUTEX PER L'ACCEPT	-
		if(init_accept_mutex()){
			print_my_error("server.init_accept_mutex");
			return 1;
		}

		// INIZIALIZZO AMBIENTE DI LOG
		if(init_log_environment()){
			print_my_error("Errore durante l'inizializzazione del file di log.");
			return 1;
		}
		
		print_my_error("Logger inizializzato.");

		///// INIZIALIZZO LE SOCKET ////
		print_my_error("Inizializzazione socket...");
		
		// INIZIALIZZO LA SOCKET PLAIN
		serverSocket = get_socket_tcp();
		if(serverSocket == GENERIC_INT_ERROR){
			print_my_error("server.get_socket_tcp.SOCKET_PLAIN");
			return 1;
		}
		if(assign_address_to_socket(serverSocket, conf.C_PORT_PLAIN)){
			print_my_error("server.assign_address_to_socket");
			return 1;
		}
		if(take_socket_in_listen_status(serverSocket, (int)conf.C_LSTN_QUEUE_LEN)){
			print_my_error("server.take_socket_in_listen_status");
			return 1;
		}
		
		//INIZIALIZZO SE RICHIESTA LA SOCKET PER LA CIFRATURA
		if(conf.C_PROCS_THREAD_ENCI != 0){	
			serverSocket_enc = get_socket_tcp();
			if(serverSocket_enc == GENERIC_INT_ERROR){
				print_my_error("server.get_socket_tcp.SOCKET_FOR_ENC");
				return 1;
			}
			assign_address_to_socket(serverSocket_enc, conf.C_PORT_ENCIPHER);
			take_socket_in_listen_status(serverSocket_enc, (int)conf.C_LSTN_QUEUE_LEN);
		}
		print_my_error("Socket create con successo!");
		
		////////////////////////////////////////
		
		// MODALIT' MULTITHREAD
		if (conf.C_MODE_THREAD){
			print_my_error("Creazione dei thread...");
			#ifndef _WIN32
			if(pthread_key_create(&busy_key, NULL)){
				print_my_error("server.pthread_key_create");
				return 1;
			}
			#endif
			crea_pool_di_thread(&thread_arr_plain, conf.C_MODE_THREAD, NOT_CYPH);
			if(conf.C_PROCS_THREAD_ENCI){
				crea_pool_di_thread(&thread_arr_enc, conf.C_PROCS_THREAD_ENCI, CYPH);
			}
		}
		// MODALITA' MULTI-PROCESSO
		else{
			// CREO SPAZIO INDIRIZZAMENTO
			print_my_error("Creazione dei processi...");
			if(crea_pool_di_processi(&procs_arr_plain, conf.C_MODE_PROCESS, NOT_CYPH)){
				print_my_error("server.crea_pool_di_processi.IN_CHIARO");
				return 1;
			}
			
			if(conf.C_PROCS_THREAD_ENCI){
				if(crea_pool_di_processi(&procs_arr_enc, conf.C_PROCS_THREAD_ENCI, CYPH)){
					print_my_error("server.crea_pool_di_processi.PER_CIFRATURA");
					return 1;
				}
			}
		}
		
		print_my_error("Server is Running!");
		
		// RIMANE IN ATTESA DI UN EVENTO TASTIERA
	
		attesa_evento_tastiera();

		// UNIX
		#ifndef _WIN32
		if(last_signal == SIGHUP)
			manage_sighup();	
		else
			manage_sigterm();

		last_signal = 0;
		#endif
	}

	return 0;
}

#ifndef _WIN32
int deamonize(){
	pid_t pid = fork();
	if (pid == -1) {
		print_my_error("server.demonize.fork");
		return GENERIC_INT_ERROR;
	}
	else if(pid != 0)
		exit(EXIT_SUCCESS);
	
	pid_t ss_id = setsid();
	if(ss_id == -1){
		print_my_error("server.demonize.setsid");
		return GENERIC_INT_ERROR;
	}
	signal(SIGHUP, SIG_IGN);
	pid = fork();
	if (pid == -1) {
		print_my_error("server.demonize.fork");
		return GENERIC_INT_ERROR;
	}
	else if(pid != 0)
		exit(EXIT_SUCCESS);
	if(chdir("/")){
		print_my_error("server.deamonize.chdir");
		return GENERIC_INT_ERROR;
	}
	umask(S_IWGRP | S_IWOTH);
	
	int i;
	for ( i=getdtablesize(); i>=0; --i)						/* chiudo tutti i descrittori ereditati */
		close(i);			
	
	int fd = open("/dev/null", O_RDWR);
	if (fd != -1) {   
		dup2 (fd, STDIN_FILENO);
		dup2 (fd, STDOUT_FILENO);
		dup2 (fd, STDERR_FILENO);
		
		if (fd > 2)
			close (fd);
	}
	else
		return GENERIC_INT_ERROR;
	errno = 0;
	return 0;
}
#endif

/*
 *	Controllo che venga fornito il file di configurazione e ne prende il valore.
 */
int check_arguments(int argc, char **argv){
	
	if(argc > 3){
		print_my_error("Sintassi del comando errata.\n");
		return GENERIC_INT_ERROR;
	}
	if(argc < 3){
		print_my_error("File di configurazione manacante.\n");
		return GENERIC_INT_ERROR;
	}
	if(!strcmp(argv[1], FLAG_CONGIF)){
		if( (conf.C_NAMEPATH_FILE_CONF = strcpy_da_a(argv[2], 0, strlen(argv[2]) - 1)) == NULL ){
			print_my_error("Sintassi comando errata.\n");
			return GENERIC_INT_ERROR;
		}
	}
	else{
		print_my_error("Sintassi del comando errata.\n");
		return GENERIC_INT_ERROR;
	}

	return 0;
}

/*
 *	Inizializza l'handler dei segnali/eventi in base all'OS
 */
int set_console_handler(){
#ifdef _WIN32
	//	IMPOSTO GLI HANDLER PER EVENTI CONSOLE
	if(!SetConsoleCtrlHandler(CtrlHandler, TRUE)){
		print_my_error("utility.set_console_handler.FAILED_CREATING_CONSOLE_CONTROL_HANDLER");
		return GENERIC_INT_ERROR;
	}

	// INIZIALIZZO L'EVENTO "ATTESA EVENTO TASTIERA"
	event_keyboard = CreateEventA(NULL, FALSE, FALSE, NULL);
	if(event_keyboard == NULL){
		print_my_error("server.set_console_handler.CreateEventA");
		return GENERIC_INT_ERROR;
	}
#else
	signal(SIGHUP,signal_handler);
	signal(SIGTERM, manage_sigterm);
	signal(SIGUSR1, manage_sigterm_thread);			//  FA TERMINARE IL THREAD SE LIBERO
#endif

	return 0;
}

//////////////////////////////////////////////////////// FUNZIONI WINDOWS ////////////////////////////////////////////////////////////

#ifdef _WIN32

DWORD WINAPI thread_task(LPVOID flag_encipher){
	
	// VARIABILI PER GESTIRE LA REQUEST DI UN CLIENT
	socket_descriptor_t cl;
	http_request_t req;
	init_request(&req);
	DWORD res = 0;

	// PROCESSO SERVER 
	while(1){
		//	CONTROLLO SE DEVO TERMINARE
		res = WaitForSingleObject(event_autokill_thread, 0);			 				// Se l'evento è segnalato termina, altrimenti esce per timeout
		if(res == WAIT_OBJECT_0)														
			ExitThread(EXIT_SUCCESS);
		else if(res == WAIT_ABANDONED || res == WAIT_FAILED){
			print_my_error("server.thread_task.WaitForSingleObject.event_autokill_thread");
			ExitProcess(EXIT_FAILURE);
		}

		// RIMANE IN ATTESA DI UN CLIENT AUTENTICATO
		authenticated_client(flag_encipher ? serverSocket_enc :  serverSocket			// metto in ascolto sulla giusta porta	
								, &cl, &req, (int)flag_encipher);

		// SEZIONE A MUTUA ESCLUSIONE PER LEGGERE nBusy
		if(WaitForSingleObject(mux_nBusy, INFINITE) == WAIT_FAILED){
			print_my_error("server.thread_task.WaitForSingleObject.mux_nBusy");
			ExitProcess(EXIT_FAILURE);
		}

		if(nBusy == 0){																		// 	Se sono il primo thread occupato, allora setto lo stato dell'evento
			res = WaitForSingleObject(event_not_busy, 0); 							//	a non segnalato.
			if(res == WAIT_FAILED || res == WAIT_ABANDONED)
				ExitProcess(EXIT_FAILURE);
		}

		nBusy++;

		if(!ReleaseMutex(mux_nBusy))
			ExitProcess(EXIT_FAILURE);
		
		// CREO RESPONSE E LA INZIALIZZO
		http_response_t resp;
		init_response(&resp);
		
		// MESSAGGIO HTTP DI RISPOSTA
		HTTP_MESSAGE msg;
		size_t len_msg;

		// GESTISCO REQUEST
		if(!manage_http_request(&req, &resp, (int)flag_encipher, ip_to_uint(&req.cl_addr))){
			set_content_type(TEXT_PLAIN, NULL, &resp);
			set_content_length(&resp);
		}
		else{
			char err_msg[] = "ERRORE INTERNO!";
			set_status_line(CODE_500, &resp);
			set_body(err_msg, strlen(err_msg), &resp);
		}
		append_common_log_format(&req, &resp,(int) flag_encipher);
		assemble_response(&resp, &len_msg, &msg);
		
		// SPEDISCO MESSAGGIO
		send(cl, msg, len_msg, 0);
		shutdown(cl, SD_SEND);
		my_close_socket(cl);
		
		// LIBERO RISORSE
		free(msg);
		
		free_http_response(&resp);
		free_http_request(&req);

		// SEZIONE A MUTUA ESCLUSIONE PER LEGGERE nBusy
		if(WaitForSingleObject(mux_nBusy, INFINITE) == WAIT_FAILED){	
			print_my_error("server.thread_task.WaitForSingleObject.mux_nBusy");
			ExitProcess(EXIT_FAILURE);	
		}

		nBusy--;		
	
		if(nBusy == 0) 																					// 	se sono l'ultimo thread occupato allora
			SetEvent(event_not_busy);																	//	setto lo stato dell'evento a segnalato

		if(!ReleaseMutex(mux_nBusy))
			ExitProcess(EXIT_FAILURE);
	}
}

void manage_ctrl_c(){
	int res = 0;
	// SE IN MODALITA' MULTI-PROCESS
	if(conf.C_MODE_PROCESS){
		printf("Attendo che tutti i processi terminino...\n");
		int i;	
		for(i=0; i<conf.C_MODE_PROCESS; i++)
			WaitForSingleObject(procs_arr_plain[i].hProcess, INFINITE);
		if(conf.C_PROCS_THREAD_ENCI){
			for(i=0; i<conf.C_PROCS_THREAD_ENCI; i++)
				WaitForSingleObject(procs_arr_enc[i].hProcess, INFINITE);
			free(procs_arr_enc);
		}
		free(procs_arr_plain);
		printf("Terminati tutti i processi...\n");

		printf("Chiudo le socket...\n");
		i = 0;
		if(conf.C_PROCS_THREAD_ENCI)
			i |= closesocket(serverSocket_enc);
		i |= closesocket(serverSocket);
		WSACleanup();

		// CONTROLLO ERRORI NELLA CHIUSURA SOCKET
		if(i){
			print_my_error("Errore nella chiusura delle socket.\n");
			ExitProcess(EXIT_FAILURE);
		}

		// PULISCO STRUTTURA CONFIGURAZIONE
		cleanup_config_struct(&conf);
		
		// RISVEGLIO IL MAIN THREAD, 
		if(!SetEvent(event_keyboard))
			ExitProcess(EXIT_FAILURE);
		printf("Inizializzo il server con i nuovi parametri...\n");
	}

	// ALTRIMENTI IN MODALITA MULTI-THREAD
	else{
		if(!SetEvent(event_autokill_thread)){					
			print_my_error("server.manage_ctrl_c.SetEvent");
			ExitProcess(EXIT_FAILURE);
		}

		// INIZIALIZZO IL NUOVO PROCESSO E TERMINO
		STARTUPINFOA strp_info;
		PROCESS_INFORMATION proc_info;
		ZeroMemory(&proc_info,sizeof(PROCESS_INFORMATION));
		ZeroMemory(&strp_info,sizeof(STARTUPINFO));
		char child_proc_path[MAX_PATH_LEN];
		_getcwd(child_proc_path, MAX_PATH_LEN);
		strcat(child_proc_path, MAIN_PROC_NAME);
		char params[MAX_PATH_LEN];
		params[0] = '\0';
		strcat(params, MAIN_PROC_NAME);
		strcat(params, " ");
		strcat(params, FLAG_CONGIF);
		strcat(params, " ");
		strcat(params, conf.C_NAMEPATH_FILE_CONF);
		printf("Inizializzo il server con i nuovi parametri...\n");

		// ATTENDO CHE I THREAD ABBIANO TERMINATO IL TASK
		res = WaitForSingleObject(event_not_busy, INFINITE);
		if(res == WAIT_FAILED || res == WAIT_ABANDONED){
			print_my_error("server.manage_ctrl_c.WaitForSingleObject");
			ExitProcess(EXIT_FAILURE);
		}
		// CREO IL NUOVO PROCESSO 
		if(!CreateProcessA(child_proc_path, params, NULL, NULL, FALSE, 0, NULL, NULL, &strp_info, &proc_info)){
			print_my_error("server.CtrlHandler.CreateProcess");
			ExitProcess(EXIT_FAILURE);
		}

		// TERMINO
		ExitProcess(EXIT_SUCCESS);		
	}
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType){
	if(fdwCtrlType == CTRL_C_EVENT){
		printf("\nRichiesta di rilettura file configurazione presa in carico...\n");
		manage_ctrl_c();
		return TRUE;
	}
	else
		return FALSE;
}

void attesa_evento_tastiera(){
	WaitForSingleObject(event_keyboard, INFINITE);
}

void crea_pool_di_thread(HANDLE **threads_array, int threads_to_create, MODE flag_encipher){
	if( (event_autokill_thread = CreateEventA(NULL, TRUE, FALSE, NULL)) == NULL){
		print_my_error("server.crea_pool_di_thread.CreateEventA");
		ExitProcess(EXIT_FAILURE);
	}
	if( (mux_nBusy = CreateMutexA(NULL, FALSE, NULL)) == NULL){
		print_my_error("server.crea_pool_di_thread.CreateMutexA");
		ExitProcess(EXIT_FAILURE);
	}
	if( (event_not_busy = CreateEventA(NULL, FALSE, TRUE, NULL)) == NULL){
		print_my_error("server.crea_pool_di_thread.CreateEventA");
		ExitProcess(EXIT_FAILURE);
	}
	*threads_array = (HANDLE *) malloc(sizeof(HANDLE)*threads_to_create);
	if(threads_array == NULL){
		print_my_error("server.crea_pool_di_thread.malloc");
		ExitProcess(EXIT_FAILURE);
	}
	int i;
	for(i=0; i<threads_to_create; i++){
		(*threads_array)[i] = CreateThread(NULL, 0, thread_task, (void *) flag_encipher, 0, NULL);
		if((*threads_array)[i] == NULL){
			print_my_error("server.crea_pool_di_thread.CreateThread");
			ExitProcess(EXIT_FAILURE);
		}
	}
}

int crea_pool_di_processi(PROCESS_INFORMATION **procs_arr, int procs_to_create, MODE flag_encipher){
	int i;
	*procs_arr = (PROCESS_INFORMATION *) malloc(sizeof(PROCESS_INFORMATION)*procs_to_create);
	if(*procs_arr == NULL){
		print_my_error("server.crea_pool_di_processi.malloc");
		return GENERIC_INT_ERROR;
	}
	for(i=0; i<procs_to_create; i++){
		if(fork_process(&((*procs_arr)[i]), flag_encipher)){
			print_my_error("server.crea_pool_di_processi.fork_process");
			if(kill_processes_pool(i-1, *procs_arr, (int) procs_to_create))	
				print_my_error("server.crea_pool_di_processi.kill_processes_pool");
			free(*procs_arr);
			return GENERIC_INT_ERROR;
		}
	}
	return 0;
}

// threads = i thread da terminare
// n_threads: numero di threads da terminare
void kill_thread_pool(HANDLE *threads, int n_threads){
	int i;
	for(i=0; i<n_threads; i++){
		if(!TerminateThread(threads[i], EXIT_SUCCESS)){
			print_my_error("server.kill_thread_pool.TerminateThread");
			ExitProcess(EXIT_FAILURE);
		}
	}
}

//  inivia evento CTRL+BREAK a tutti i processi nel pool
//	se j==0 allora termina tutti.
int kill_processes_pool(int j, PROCESS_INFORMATION *procs_arr, int len_arr){
	int i;
	j = ((j == 0 || j>=len_arr) ? len_arr : j);
	int res = 0;
	for(i=0; i<j; i++){
		if(!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,procs_arr[i].dwProcessId)){
			print_my_error("server.kill_processes_pool.GenerateConsoleCtrlEvent.FALLITA_CTRL_C_QUINDI_INVIO_CTRL_BREAK");
			res++;
			if(!TerminateProcess(procs_arr[i].hProcess, EXIT_FAILURE))
				print_my_error("server.kill_processes_pool.TerminateProcess.ERRORE_INVIO_CTRL_BREAK");
		}
		if(WaitForSingleObject(procs_arr[i].hProcess, INFINITE) == WAIT_FAILED){
			print_my_error("server.kill_processes_pool.WaitForSingleObject");
			res++;
		}
		CloseHandle(procs_arr[i].hProcess);
	}
	if(res)
		return GENERIC_INT_ERROR;
	return 0;
}

int fork_process(PROCESS_INFORMATION *proc_info_out, MODE flag_encipher){
	// https://stackoverflow.com/questions/670891/is-there-a-way-for-multiple-processes-to-share-a-listening-socket
	
	// CREO NAMED PIPE PER IL TRASFERIMENTO DELLA STRUTTURA WSAPROTOCOL_INFO
	char pipe_name[] = "\\\\.\\pipe\\pipe_init_socket";
	const size_t pipe_size = sizeof(WSAPROTOCOL_INFO);
	HANDLE pipe;
	if( (pipe = CreateNamedPipeA(pipe_name,PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | 
				PIPE_WAIT | PIPE_READMODE_MESSAGE, 2, pipe_size, pipe_size,0, NULL)) == INVALID_HANDLE_VALUE){
		print_my_error("server.fork_process.CreateNamedPipeA");
		return GENERIC_INT_ERROR;
	}

	// CREO EVENTO PER LA SEGNALAZIONE DI "AVVENUTA LETTURA"/"PROCESSO PRONTO"
	char event_read_name[] = "sync_process";
	HANDLE event_read = CreateEventA(NULL, FALSE, FALSE, event_read_name);
	
	// MEMORY MAP PER CONDIVIDERE I PARAMETRI NELLA STRUTTURA "share_params", TRA I PROCESSI
	HANDLE mem_shr = CreateFileMappingA(INVALID_HANDLE_VALUE
									,NULL
									,PAGE_READWRITE
									,0
									,sizeof(struct share_params)
									,MEM_PROC_SHRD_NAME);
	if(mem_shr == NULL){
     	print_my_error("server.fork_process.CreateFileMappingA");
      	return GENERIC_INT_ERROR;
  	}

	// APRO LA VIEW
	struct share_params *pt_shr_par = (struct share_params *) MapViewOfFile(mem_shr, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct share_params));
	if(pt_shr_par == NULL){
		print_my_error("server.fork_process.MapViewOfFile");
		return GENERIC_INT_ERROR;
	}

	// SCRIVO IN MEMORIA CONDIVISA I PARAMETRI DA PASSARE AL NUOVO PROCESSO
	CopyMemory(pt_shr_par->path_file_passwd, conf.C_PATH_PASSWD, strlen(conf.C_PATH_PASSWD));
	CopyMemory(pt_shr_par->pat_dir_file_log, conf.C_DIR_FILE_LOG, strlen(conf.C_DIR_FILE_LOG));
	CopyMemory(pt_shr_par->pipe_name, pipe_name, strlen(pipe_name));
	CopyMemory(pt_shr_par->event_read_name, event_read_name, strlen(event_read_name));
	CopyMemory(pt_shr_par->name_file_log, name_file_log, strlen(name_file_log));
	pt_shr_par->port_plain = conf.C_PORT_PLAIN;
	pt_shr_par->port_encyp = conf.C_PORT_ENCIPHER;
	UnmapViewOfFile(pt_shr_par);																							// chiudo la view per liberare spazio indirizzi processo						

	// INIT STRUTTURE PER LA CREAZIONE PROCESSO
	STARTUPINFOA strp_info;
	PROCESS_INFORMATION proc_info;
	ZeroMemory(&proc_info,sizeof(PROCESS_INFORMATION));
	ZeroMemory(proc_info_out,sizeof(PROCESS_INFORMATION));
	ZeroMemory(&strp_info, sizeof(STARTUPINFO));
	strp_info.cb = sizeof(STARTUPINFO);

	// INIZIALIZZO STRINGA PARAMETRI DA PASSARE AL NUOVO PROCESSO
	char arguments_proc[128];
	arguments_proc[0] = '\0';
	strcat(arguments_proc, MEM_PROC_SHRD_NAME);
	strcat(arguments_proc, " ");
	char inttostr[4];
    sprintf(inttostr, "%d", flag_encipher); 
	strcat(arguments_proc, inttostr);
	char proc_path[MAX_PATH_LEN];
	_getcwd(proc_path, MAX_PATH_LEN);
	strcat(proc_path, CHILD_PROC_NAME);

	// CREO IL PROCESSO INZIALIZZANDO UN GRUPPO DI PROCESSI
	if(!CreateProcessA(proc_path,arguments_proc, NULL, NULL, FALSE,
					0, NULL, NULL, &strp_info, &proc_info) ){
		print_my_error("server.fork_process.CreateProcessA");
		// termina i processi finora creati
		TerminateProcess(proc_info.hProcess, 1);
		return GENERIC_INT_ERROR;
	}

	// DUPLICO IL SOCKET DESCR. PER IL PROCESSO CREATO E OTTENGO LA STRUTTURA PER LA DUPLICAZIONE
	WSAPROTOCOL_INFO wsa_proto;
	if(WSADuplicateSocketA(flag_encipher == CYPH ? serverSocket_enc : serverSocket		// DUPLICO LA SOCKET RICHIESTA
							, proc_info.dwProcessId, &wsa_proto)){
		print_my_error("server.fork_process.WSADuplicateSocket");
		// termina i processi finora creati
		TerminateProcess(proc_info.hProcess, 1);
		return GENERIC_INT_ERROR;
	}
	
	// SCRIVO LA STRUTTURA SULLA PIPE
	DWORD byte_wr;

	// RIMANGO IN ATTESA CHE IL PROCESSO CREATO ABBIA APERTO LA PIPE
	ConnectNamedPipe(pipe, NULL);

	// SCRIVO SULLA PIPE LA STRUTTURA PER LA DUPLICAZIONE DELLA SOCKET
	if(!WriteFile(pipe, (char *)&wsa_proto, sizeof(wsa_proto), &byte_wr,NULL)){
		print_my_error("server.WriteFile.SCRITTURA_SU_PIPE");
		return GENERIC_INT_ERROR;
	}

	// RIMANGO IN ATTESA DI AVVENUTA LETTURA
	WaitForSingleObject(event_read, INFINITE);

	// CHIUDO L'HANDLE DELLA PIPE
	CloseHandle(pipe);

	//COPIO LA STRUTTURA PROCESS_INFORMATION PER RITORNARLA AL CHIAMANTE
	CopyMemory(proc_info_out, &proc_info, sizeof(PROCESS_INFORMATION));

	return 0;
}

#endif

//////////////////////////////////////////////////////// FUNZIONI UNIX-LIKE //////////////////////////////////////////////////////////////

#ifndef _WIN32

void thread_task(MODE flag_encipher){
	
	// VARIABILI PER GESTIRE LA REQUEST DI UN CLIENT
	socket_descriptor_t cl;
	http_request_t req;
	init_request(&req);
	
	int busy = 0;
	if(conf.C_MODE_THREAD)
		pthread_setspecific(busy_key, &busy);
	else {
		// REINSTALL DEFAULT SIG-HANDLER
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
	}

	while(1){
		// CONTROLLO SE OCCORSO SEGNLE IN CASO TERMINO
		if(last_signal && conf.C_MODE_THREAD)									
			pthread_exit(NULL);
		else if(last_signal && conf.C_MODE_PROCESS){
			exit(EXIT_SUCCESS);
		}
		
		// RIMANE IN ATTESA DI UN CLIENT AUTENTICATO
		authenticated_client(((int)flag_encipher) ? serverSocket_enc : serverSocket
									, &cl, &req, (int)flag_encipher);	
		
		// SONO IMPEGNATO
		if (conf.C_MODE_THREAD) {
			busy++;
			pthread_setspecific(busy_key, &busy);
		}
		else 
			process_busy++;
		
		// CREO RESPONSE E LA INZIALIZZO
		http_response_t resp;
		init_response(&resp);

		// MESSAGGIO HTTP DI RISPOSTA
		HTTP_MESSAGE msg;
		size_t len_msg;
		
		// GESTISCO REQUEST
		if(!manage_http_request(&req, &resp, (int) flag_encipher, ip_to_uint(&req.cl_addr))){
			set_content_type(TEXT_PLAIN, NULL, &resp);
			set_content_length(&resp);
		}
		else{
			char err_msg[] = "ERRORE INTERNO!";
			set_status_line(CODE_500, &resp);
			set_body(err_msg, strlen(err_msg), &resp);
		}
		
		append_common_log_format(&req, &resp,flag_encipher);
		assemble_response(&resp, &len_msg, &msg);
		
		// SPEDISCO MESSAGGIO
		send(cl, msg, len_msg, 0);
		shutdown(cl, SHUT_WR);
		my_close_socket(cl);
		
		// LIBERO RISORSE
		free(msg);
		
		free_http_response(&resp);
		free_http_request(&req);
		
		// HO FINITO
		if(conf.C_MODE_THREAD){
			busy = 0;
			pthread_setspecific(busy_key, &busy);
		}
		else
			process_busy = 0;
	}
}

void attesa_evento_tastiera(){
	pthread_cond_wait(&event_keyboard, &mux_event_keyboard);
}

void crea_pool_di_thread(pthread_t **threads_arr, int threads_to_create, MODE flag_encipher){
	*threads_arr = (pthread_t *) malloc(sizeof(pthread_t)*threads_to_create);
	if (threads_arr == NULL) {
		print_my_error("server.crea_pool_di_thread.malloc");
		exit(EXIT_FAILURE);
	}
	int i;
	for (i=0; i<threads_to_create; i++) {
		if(pthread_create(&(*threads_arr)[i], NULL, thread_task,(void *) flag_encipher)){
			print_my_error("server.crea_pool_di_thread.pthread_create");
			exit(EXIT_FAILURE);
		}
	}
}

int crea_pool_di_processi(pid_t **procs_arr, int len_arr, MODE flag_encipher){
	int i;
	*procs_arr = (pid_t *) malloc(sizeof(pid_t)*len_arr);
	if(*procs_arr == NULL) 
		return GENERIC_INT_ERROR;
	for (i=0; i<len_arr; i++) {
		pid_t ch = fork();
		if(!ch)
			thread_task(flag_encipher);
		else if(ch == -1){
			print_my_error("server.crea_pool_di_processi.fork");
			kill_processes_pool(*procs_arr, i-1, len_arr);
			exit(EXIT_FAILURE);
		}
		else{
			(*procs_arr)[i] = ch;
		}
	}
	return 0;
}

// killa i primi j processi, se j == 0 killa tutto 
int kill_processes_pool(pid_t *procs_arr, int j, int len_arr){
	int i;
	int res = 0;
	j = (j == 0 ? len_arr : j);
	for (i=0; i<j ; i++) {
		int stat;
		res |= kill(procs_arr[i], SIGUSR1);
		res |= waitpid(procs_arr[i], &stat, 0) == -1;
		res |= !WIFEXITED(stat);
	}
	if (res) {
		print_my_error("server.kill_processes_pool");
		return GENERIC_INT_ERROR;
	}
	return 0;
}

int kill_thread_pool(pthread_t *threads_arr, int len_arr, int sig){
	int i;
	for (i=0; i<len_arr; i++) {
		if(pthread_kill(threads_arr[i], sig)) 
			return 1;
		if(pthread_join(threads_arr[i], NULL))
			return 1;
	}
	
	return 0;
}

void manage_sighup(){
	print_my_error("Richiesta di rilettura file di configurazione presa in carico\n");
	
	if (conf.C_MODE_THREAD) {
		if(kill_thread_pool(thread_arr_plain, conf.C_MODE_THREAD, SIGUSR1))
			exit(EXIT_FAILURE);
		free(thread_arr_plain);
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
		if(conf.C_PROCS_THREAD_ENCI){
			if(kill_thread_pool(thread_arr_enc, conf.C_PROCS_THREAD_ENCI,SIGUSR1))
				exit(EXIT_FAILURE);
			free(thread_arr_enc);
			shutdown(serverSocket_enc, SHUT_RDWR);
			close(serverSocket_enc);
		}
	}
	else	{								
		int res = 0;
		res |= kill_processes_pool(procs_arr_plain, 0, conf.C_MODE_PROCESS);
		free(procs_arr_plain);
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
		if(conf.C_PROCS_THREAD_ENCI){
			res |= kill_processes_pool(procs_arr_enc, 0, conf.C_PROCS_THREAD_ENCI);
			free(procs_arr_enc);
			shutdown(serverSocket_enc, SHUT_RDWR);
			close(serverSocket_enc);
		}
		if(res){
			print_my_error("server.manage_sighup.kill_processes_pool");
			exit(EXIT_FAILURE);
		}
	}
	destroy_mutex_or_sem();
}

void signal_handler(int sig){
	if(sig == SIGHUP){
		last_signal = sig;
		pthread_cond_signal(&event_keyboard);		// sveglia il main thread e riprende la sua esecuzione
	}
}

void manage_sigterm(){
	print_my_error("Termino tutti i processi/thread...\n");
	int res = 0;
	res |= kill_processes_pool(procs_arr_plain, 0, conf.C_MODE_PROCESS);
	free(procs_arr_plain);
	if(conf.C_PROCS_THREAD_ENCI){
		res |= kill_processes_pool(procs_arr_enc, 0, conf.C_PROCS_THREAD_ENCI);
		free(procs_arr_enc);
	}
	if(res){
		print_my_error("server.manage_sigterm.kill_processes_pool");
		exit(EXIT_FAILURE);
	}
	print_my_error("Ciao!\n");
	exit(EXIT_SUCCESS);
}

// Viene chiamata anche da un child-process/thread
void manage_sigterm_thread(){
	if(conf.C_MODE_THREAD){
		int *busy  = (int *) pthread_getspecific(busy_key);
		if(!*busy)								// se non e' impegnato termina
			pthread_exit(NULL);
	}
	else {
		if (!process_busy) {
			exit(EXIT_SUCCESS);
		}	
		last_signal = SIGTERM;
	}
}

#endif