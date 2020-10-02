#ifdef _WIN32	
	#include <windows.h>
#else
	#include <pthread.h>
	#include <errno.h>
	#include <unistd.h>
	#include <sys/mman.h>
	#include <fcntl.h>
#endif
#include <stdio.h>
#include <string.h>
#include "functionality.h"
#include "list.h"
#include "mime_type_utility.h"
#include "utility.h"

// NOMI STANDARD
#define PIPECMD_BASENAME "\\\\.\\pipe\\pipe_for_cmd_"
#define WC_BLANC '$'	/* sostituisce il ' ' */
#define WC_SLASH '%'   	/* sostituisce il '/' */

// DIMENSIONI STANDARD
#define BUFF_READ 16																// lubnghezza buffer di lettura per read e ReadFile	
#define PIPE_SIZE 64

// CODICI DI INFORMAZIONE LOCALI
#define PUT_ALREADY_EXIST_FILE 100                  									// il metodo put ha sovrascritto un file
#define PUT_NEW_FILE 101                            									// Il metodo put ha creato un nuovo file
#define PUT_ERROR_NOBODY 110                        									// IL metodo e' put ma manca il body

// MESSAGGI PER IL CLIENT
#define PUT_NEW_FILE_MSG	"FILE CREATO\n"											
#define PUT_ALREADY_EXIST_FILE_MSG	"FILE ESISTENTE, SOVRASCRITTO"
#define FILENOEX "NO SUCH FILE OR DIRECTORY"
#define PUT_FILE_EMPTY "FILE PUTTED IS EMPTY, NOT CREATED"
#define GET_FILE_EMPTY "REQUESTED FILE EMPTY"
#define CMD_NOT_VALID "COMANDO NON VALIDO"



/*
 *	Struttura per il passaggio dei parametri a 'execute_command_thread'
 */
struct params_thread{
	CMD cmd_name;
	char **p_output_cmd;																// puntatore ad out_buff
	size_t *output_len;																	// dimensione dll'output
	size_t *output_cmd_size;															// Dimensione dello spazio allocato in *p_output_cmd
	#ifdef _WIN32
	HANDLE h_event;	
	#else
	pthread_cond_t *cond_vrb;
	#endif
};

int manage_http_request(http_request_t *request, http_response_t *resp, MODE m, unsigned int seed){
	HTTP_REQUEST_METHOD meth = request->method;
	
	if(strcmp(meth,HTTP_METH_GET) == 0)
		return manage_get_method(request, resp, m, seed);
	if(strcmp(meth,HTTP_METH_PUT) == 0)
		return manage_put_method(request, resp);
	
	return GENERIC_INT_ERROR;
}

int manage_get_method(http_request_t *request, http_response_t *resp, MODE m, unsigned int seed){ 		
	// RESULT: VALE 0 SE OK, ERRORE ALTRIMENTI
	int result = 0;
	CMD cmd;
	// PATH/COMANDO
	PATH path;
	
	// RICAVO TIPO DEL PATH 
	URI_TYPE u_type = get_uri_type(request->uri, &path);				// non individua quando il path corrisp. a una directory
	switch (u_type)
	{
		// RICHIESTA DI FILE
		case URI_IS_FILE:
			result |= get_response_file(path, resp, m, seed);
			break;

		// RICHIESTA CONTENUTO DIRECTORY
		case URI_IS_DIR:
		
			// WINDOWS
			#ifdef _WIN32
			cmd = my_strcat("dir /B ", path);
		
			// UNIX
			#else
			cmd = my_strcat("ls -la ", path);

			#endif

			result |= get_response_command(cmd, resp);
			free(cmd);
			break;

		// RICHIESTA ESECUZIONE DI COMANDO
		case URI_IS_CMD:
			result |= get_response_command((CMD)path, resp);
			break;
		
		// RICHIESTA DI COMANDO MA IL COMANDO FORNITO NON E' VALIDO
		case URI_IS_INVALID_CMD:
			path = NULL;
			result |= set_body(CMD_NOT_VALID, strlen(CMD_NOT_VALID), resp);
			set_status_line(CODE_403, resp);
			break;


		// RICHIESTA (URI) NON VALIDO
		case INVALID_URI:
			result |= set_body(FILENOEX, strlen(FILENOEX), resp);
			result |= set_status_line(CODE_403, resp);
			break;
	}

	// LIBERO RISORSE
	free(path);

	if(result)
		return GENERIC_INT_ERROR;

	return 0;
}


int manage_put_method(http_request_t *request, http_response_t *resp){
	// CONTROLLO CHE ESISTA IL CORPO
	if(!strcmp(request->method,HTTP_METH_PUT) && (request->content_length == 0 || request->body==NULL) ){					
		set_status_line(CODE_400, resp);
		set_body(PUT_FILE_EMPTY, strlen(PUT_FILE_EMPTY), resp);
		return 0;
	}
	
	int result = 0;
	int put_type = 0;
	
	//	WINDOWS
	#ifdef _WIN32

	// CONVERTO L'URI IN UN WINPATH
	PATH puttedFile_path = convert_uri_to_winpath(request->uri);
	if(puttedFile_path == GENERIC_NULL_ERROR){
		print_my_error("functionality.manage_put_method.convert_uri_to_winpath");
		return GENERIC_INT_ERROR;
	}

	// CREO IL FILE/PRENDO L'HANDLE DI UNO ESISTENTE
	SetLastError(0);
	HANDLE puttedFile_h = CreateFileA(puttedFile_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE										// apro/creo file con accesso in scrittura esclusivo
							, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(puttedFile_h == INVALID_HANDLE_VALUE){
		print_my_error("functionality.manage_put_method.CreateFile");
		return GENERIC_INT_ERROR;
	}

	// CONTROLLO SE IL FILE E' STATO CREATO OPPURE SOVRASCRITTO UNO GIA ESISTENTE
	if(GetLastError() == ERROR_ALREADY_EXISTS)
		put_type = PUT_ALREADY_EXIST_FILE;
	else
		put_type = PUT_NEW_FILE;

	// PRENDO IL LOCK
	OVERLAPPED ovllp_lock;
    ovllp_lock.Offset = 0;
    ovllp_lock.OffsetHigh = 0;
    ovllp_lock.hEvent = NULL;
	if(!LockFileEx(puttedFile_h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ovllp_lock)){
		print_my_error("functionality.manage_put_method.LockFileEx");
		CloseHandle(puttedFile_h);
		return GENERIC_INT_ERROR;
	}
	
	DWORD byte_wrten;
	if( (result |= (!WriteFile(puttedFile_h,request->body, request->content_length,&byte_wrten,NULL))) )
		print_my_error("functionality.manage_put_method.Writefile");

	if( (result |= (byte_wrten != request->content_length)) )
		print_my_error("functionality.manage_put_method.Writefile");

	// RILASCIO IL LOCK SUL FILE
	if(!UnlockFile(puttedFile_h, 0,0,MAXDWORD, MAXDWORD)){
		print_my_error("functionality.manage_put_method.UnlockFile");
		CloseHandle(puttedFile_h);
		return GENERIC_INT_ERROR;
	}

	CloseHandle(puttedFile_h);
	if(result)
		return GENERIC_INT_ERROR;

	#else
	// UNIX
	
	PATH puttedFile_path = request->uri;
	
	// DEFINISCO IL TIPO DI PUT
	if(!access(puttedFile_path, F_OK))														// controllo se il file esiste
		put_type = PUT_ALREADY_EXIST_FILE;
	else
		put_type = PUT_NEW_FILE;
	
	// APRE IL FILE PRENDENDO IL LOCK EXLUSIVO
	int file_desc = open(puttedFile_path, O_CREAT | O_RDWR | O_TRUNC | O_EXLOCK, S_IRWXU | S_IRGRP | S_IROTH);
	if(file_desc==-1){
		print_my_error("functionality.manage_put_method.open");
		close(file_desc);
		return GENERIC_INT_ERROR;
	}
	
	// SCRIVO IL FILE SU DISCO
	if(write(file_desc, request->body, request->content_length) == -1){
		print_my_error("functionality.manage_put_method.write");
		close(file_desc);
		return GENERIC_INT_ERROR;
	}
	
	close(file_desc);
	
	#endif
	// UNIX + WINDOWS
	
	result = 0;
	
	// SET HTTP RESPONSE
	result |= set_status_line(CODE_201, resp);
	switch(put_type){
		case PUT_ALREADY_EXIST_FILE:
			result |= set_body(PUT_ALREADY_EXIST_FILE_MSG, strlen(PUT_ALREADY_EXIST_FILE_MSG),resp);
			break;
			
		case PUT_NEW_FILE:
			result |= set_body(PUT_NEW_FILE_MSG, strlen(PUT_NEW_FILE_MSG), resp);
			break;
	}
	result |= set_content_type(TEXT_PLAIN, NULL, resp);
	
	if(result)
		return GENERIC_INT_ERROR;
	return 0;
}

int get_response_command(CMD cmd_name, http_response_t *resp){
	size_t output_len = 0;
	char *output = execute_command(cmd_name, &output_len);
		
	// CONTROLLO OUTPUT
	if(output == GENERIC_NULL_ERROR){
		print_my_error("functionality.get_response_command.execute_command");
		return GENERIC_INT_ERROR;
	}
		
	// ELSE
	int result = 0;
	result |= set_body(output,output_len,resp);
	result |= set_content_type(TEXT_PLAIN, NULL, resp);
	result |= set_status_line(CODE_200,resp);

	// CONTROLLO ERRORI
	if(result){
		print_my_error("functionality.get_response_command.error_in_set_response");
		return GENERIC_INT_ERROR;
	}

	// LIBERO LE RISORSE
	free(output);

	return 0;	
}


/*
 *	puo ritornare GENERIC_INT_ERROR oppure FILE_EMPTY
 */
int get_response_file(PATH name_file, http_response_t *resp, MODE m, unsigned int seed){
	int result=0;
	
	// WINDOWS
	#ifdef _WIN32
	
	// APRE IL FILE E PRENDE L'HANDLE
	HANDLE h_file = CreateFileA(name_file, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,												// apre il file con accesso in lettura esclusivo
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(h_file == INVALID_HANDLE_VALUE){
		print_my_error("functionality.get_response_file.CreateFileA");
		return GENERIC_INT_ERROR;
	}

	// PRENDO IL LOCK SUL FILE
	OVERLAPPED ovllp_lock;
    ovllp_lock.Offset = 0;
    ovllp_lock.OffsetHigh = 0;
    ovllp_lock.hEvent = NULL;
	if(!LockFileEx(h_file, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ovllp_lock)){
		print_my_error("functionality.get_response_file.LockFileEx");
		CloseHandle(h_file);
		return GENERIC_INT_ERROR;
	}

	DWORD size_file = GetFileSize(h_file, NULL);
	
	// SE IL FILE E' VUOTO
	if(size_file == 0){
		CloseHandle(h_file);
		result = FILE_EMPTY;
		if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD)){
			print_my_error("functionality.get_response_file.UnlockFile");
			CloseHandle(h_file);
			return GENERIC_INT_ERROR;
		}
		
	}
	
	#else
	// UNIX
	
	// APRE IL FILE E PRENDE LOCK ESCLUSIVO
	int file_descr = open(name_file, O_RDWR, O_EXLOCK);														
	if(file_descr == -1){
		print_my_error("functionality.get_response_file.open");
		return GENERIC_INT_ERROR;
	}
	
	FILE *stream_file = fdopen(file_descr, "r+");
	
	// RICAVO LUNGHEZZA FILE
	long file_size = get_file_size(stream_file);
	if (file_size == 0){
		fclose(stream_file);												// chiudo file_descr e stream
		result =  FILE_EMPTY;
	}
		
	#endif
	
	// WINDOWS + UNIX
	
	// CONTROLLO SE FILE VUOTO
	if (result == FILE_EMPTY){
		set_status_line(CODE_200, resp);
		set_body(GET_FILE_EMPTY, strlen(GET_FILE_EMPTY), resp);
		return 0;
	}
	
	// INIZIALIZZO BUFFER DI LETTURA E ARRAY OUTPUT
	char *output = NULL;
	size_t space_allocated = 0;
	size_t len_output = 0;
	char read_buff[BUFF_READ];
	
	// WINDOWS
	#ifdef _WIN32
	
	DWORD byte_read = 0;
	if(m == CYPH){
		// MAPPA IL FILE IN MEMORIA
		HANDLE h_map_file = CreateFileMappingA(h_file, NULL, PAGE_WRITECOPY, 0,0, NULL);		/* consente di creare viste read-only or Copy on write */
		if(h_map_file == NULL){
			print_my_error("functionality.get_response_file.CreateFileMappingA");
			
			if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD))
				print_my_error("functionality.get_response_file.UnlockFile");
			CloseHandle(h_file);
			return GENERIC_INT_ERROR;
		}

		// OTTENGO UNA VIEW AL FILE MAPPATO 
		char *p_file = (char *)MapViewOfFile(h_map_file, FILE_MAP_COPY, 0,0,0); 				/* Viene creata una vista copy-on-write */
		if(p_file == NULL){
			print_my_error("functionality.get_response_file.MapViewOfFile");
			CloseHandle(h_map_file);
			
			if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD))
				print_my_error("functionality.get_response_file.UnlockFile");
			CloseHandle(h_file);
			return GENERIC_INT_ERROR;
		}

		// CODIFICO IL FILE MAPPATO CON (COPY-ON-WRITE)
		encoding_xor_ip_same_file(&p_file, size_file, seed);
		
		// COPIO IL FILE
		result = concatenate_string(&output, &len_output, &space_allocated, p_file, size_file);
		if(result){
			print_my_error("functionality.get_response_file.contatenate_string");
			free(output);
		}
		
		if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD)){
			print_my_error("functionality.get_response_file.UnlockFile");
			CloseHandle(h_file);
			return GENERIC_INT_ERROR;
		}

		// CHIUDO FILE, FILE MAPPATO E VIEW
		if(!UnmapViewOfFile(p_file))
			print_my_error("functionality.get_response_file.UnmapViewOfFile");
		if(!CloseHandle(h_map_file))
			print_my_error("functionality.get_response_file.CloseHandle.FILE_MAPPED");
		if(!CloseHandle(h_file))
			print_my_error("functionality.get_response_file.CloseHandle.FILE");

		if(result)
			return GENERIC_INT_ERROR;
	}

	// LEGGE IL FILE (NEL CASO NON SERVA CIFRATO)
	else{
		do{
			result = ReadFile(h_file, read_buff, BUFF_READ, &byte_read, NULL);
			if(concatenate_string(&output, &len_output, &space_allocated, read_buff, (size_t)byte_read)){
				free(output);
				print_my_error("functionality.get_response_file.contatenate_string");
				
				if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD))
					print_my_error("functionality.get_response_file.UnlockFile");
				if(!CloseHandle(h_file))
					print_my_error("functionality.get_response_file.CloseHandle");
				return GENERIC_INT_ERROR;
			}
		}while(result && byte_read > 0);
	
		if(!UnlockFile(h_file, 0,0, MAXDWORD, MAXDWORD)){
			print_my_error("functionality.get_response_file.UnlockFile");
			CloseHandle(h_file);
			return GENERIC_INT_ERROR;
		}

		// CHIUDO IL FILE
		if(!CloseHandle(h_file))
			print_my_error("functionality.get_response_file.CloseHandle");
		
		if(result == 0){
			print_my_error("functionality.get_response_file.ReadFile");
			free(output);
			return GENERIC_INT_ERROR;
		}
	}
	#else
	// UNIX
	
	// FILE CON CIFRATURA
	if (m==CYPH) {
		result = 0;
		
		// CONTROLLO ERRORI
		if (file_size == -1){
			print_my_error("functionality.get_response_file.get_file_size");
			result = -1;
		}
		
		// MAPPO IL FILE
		void *addr_file = mmap(NULL, file_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, file_descr, 0);					// mappo il file in memoria copy-on-write (attrivuto MAP_WRITE)
		if(addr_file == MAP_FAILED){
			print_my_error("functionality.get_response_file.mmap");
			result = -1;
		}
		
		// CODIFICO IL FILE MAPPATO
		encoding_xor_ip_same_file((char **)&addr_file, file_size, seed);
		
		// SE NON OCCORSO ERRORE COPIO IL FILE MAPPATO
		if (!result)
			if(concatenate_string(&output, &len_output, &space_allocated, addr_file, file_size)){
				print_my_error("functionality.get_response_file.concatenate_string");
				result = -1;
			}
		
		
		// CHIUDO FILE MAPPATO
		if(munmap(addr_file, file_size)){
			print_my_error("functionality.get_response_file.munmap");
			result = -1;
		}
	}
	
	// FILE SENZA CIFRATURA
	else{
		
		// LEGGE IL FILE 
		result = 0;
		while(1){
			result = fread(read_buff, sizeof(char), BUFF_READ, stream_file);					// fread legge da stream file al piu' buff_read byte, e ritorna il numero di byte letti
			if(concatenate_string(&output, &len_output, &space_allocated, read_buff, result)){
				print_my_error("functionality.get_response_file.concatenate_string");
				result = GENERIC_INT_ERROR;
			}
			if(result <BUFF_READ){													// fread non fa distinzione tra errore e fine del file, quindi se la fine del file e' raggiunta
				if(ferror(stream_file)){													// potrebbe ritornare un numero inferiore a buff_read oppure zero, quindi controllo errore con ferrr.	
					print_my_error("functionality.get_response_file.fread");
					break;
				}
				else if(result != GENERIC_INT_ERROR){
					result = 0;													
					break;
				}
			}
		}																			// result se true allora errore
	}
	
	// CHIUDO LO STREAM
	if(result |= fclose(stream_file))
		print_my_error("functionality.get_response_file.fclose");
	
	// CONTROLLO ERRORI
	if(result){
		print_my_error("functionality.get_response_file.ERROR_ON_READ_FILE_PHASE");
		free(output);
		return GENERIC_INT_ERROR;
	}
	
	#endif
	
	result = 0;
	
	result |= set_status_line(CODE_200, resp);
	result |= set_body(output, len_output, resp);

	if(result){
		print_my_error("functionality.get_response_file.SET_RESPONSE_HTTP");
	}
	
	free(output);
	
	return result;
}


char *execute_command(CMD cmd_name, size_t *output_len){
	int errore=0;
	
	// INIZIALIZZO BUFFER PER L'OUTPUT
	char *output_cmd = NULL;															
	*output_len = 0;
	size_t output_cmd_size = 0;

	// SPLITTO I PARAMETRI/SPAZI DEL COMANDO SE ESISTONO
	replace_token(cmd_name, strlen(cmd_name), WC_BLANC, ' ');
	replace_token(cmd_name, strlen(cmd_name), WC_SLASH, '/');
	
	// DICHIARO E INIZILIAZZO STRUTTURA DEI PARAMETRI DEL THREAD
	struct params_thread params;
	params.cmd_name = cmd_name;
	params.p_output_cmd = &output_cmd;
	params.output_len = output_len;
	params.output_cmd_size = &output_cmd_size;
	
	// WINDOWS //
	#ifdef _WIN32

	//CREO EVENTO PER LA NOTIFICA DI OUTPUT DISPONIBILE E STRUTTURE ANNESSE
	SECURITY_ATTRIBUTES s_attr;
	s_attr.nLength = sizeof(SECURITY_ATTRIBUTES);									// dimensione della struttura s_attr
	s_attr.bInheritHandle = TRUE;													// l'handle dell'evento potra cosi essere ereditato
	s_attr.lpSecurityDescriptor = NULL;
	HANDLE h_event_0 = CreateEventA(&s_attr											// Creo l'evento														
								,FALSE												// di tipo automatic-rest 
								,FALSE												// e stato iniziale non-segnalato
								,"output_ready");
	// HANDLE EVENTO
	params.h_event = h_event_0;

	// CREO IL THREAD CHE FARÀ PARTITRE IL PROCESSO DI ESECUZIONE DEL COMANDO
	DWORD cmd_thread_exit_code;
	HANDLE cmd_thread = CreateThread(
		NULL,			                                        					// Default security
		0,				                                        					// Default stack size
		execute_command_thread,                                 					// thread function name
		(PVOID)&params,	                                        					// argomenti di thread_main
		0,				                                        					// il thread creato e' viene subito eseguito
		NULL);		                                            					// id thread
    
	// RIMANE IN ATTESA CHE L'EVENTO "OUTPUT_READY" SIA SEGNALATO   
	if(WaitForSingleObject(h_event_0,INFINITE) == WAIT_FAILED){						// in attesa dell'output dell'altro thread
		print_my_error("functionality.WaitForSingleObject");
		errore++;		
	}

	// ATTENDO CHE IL THREAD TERMINI
	if(WaitForSingleObject(cmd_thread, INFINITE) == WAIT_FAILED){				
		print_my_error("functionality.WaitForSingleObject");
		errore++;	
	}

	// OTTENGO L'EXIT-CODE DEL THREAD TERMINATO E CONTROLLO CHE NON SIA OCCORSO ERRORE
	if(!GetExitCodeThread(cmd_thread,(LPDWORD)&cmd_thread_exit_code)){				
		print_my_error("functionality.execute_command.GetExitCodeThread");
		errore++;	
	}												
	
	// CONTROLLO ERRORI SUL THREAD CHIUSO
	if(cmd_thread_exit_code == EXIT_FAILURE){										
		print_my_error("functionality.execute_command: EXIT_FAILURE");
		errore++;	
	}
	
	// CHIUDO L'HANDLE DEL THREAD
	CloseHandle(cmd_thread);
	
	// CHIUDO L'HANDLE DELL'EVENTO
	CloseHandle(h_event_0);

	if(errore){
		free(output_cmd);
		output_cmd = GENERIC_NULL_ERROR;
	}
	
	#else
	// UNIX 
	
	pthread_t id_thread;
	int exit_val;
	
	// INIZIALIZZO COND VARIABLE E MUTEX ANNESSO PER SEGNALAZIONE COMANDO ESEGUITO 
	pthread_cond_t cond_vrb = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t mux = PTHREAD_MUTEX_INITIALIZER;
	params.cond_vrb = &cond_vrb;
	
	// CREO IL THREAD CHE ESEGUIRA IL COMANDO
	if(pthread_create(&id_thread, NULL, (void *)&execute_command_thread, (void*)&params)){
		print_my_error("functionality.execute_command.pthread_create");
		return NULL;
	}
	
	// RIMANGO IN ATTESA CHE IL COMANDO SIA ESEGUITO
	if(pthread_cond_wait(&cond_vrb, &mux))
		print_my_error("functionality.execute_command.pthread_cond_wait");
	
	// RIMANGO IN ATTESA CHE IL PROCESSO TERMINI
	errore = pthread_join(id_thread,(void *)&exit_val);
	
	// RESETTO errno
	errno = 0;
	if(errore){
		char err_msg[80];
		sprintf(err_msg, "functionality.execute_command.pthread_join : Error number %d", errore);
		print_my_error(err_msg);
	}
	
	if(exit_val){
		free(output_cmd);
		print_my_error("functionality.execute_command.THREAD_EXIT_FALIURE");
		return GENERIC_NULL_ERROR;
	}
	
	#endif
		
	return output_cmd;
}

#ifndef _WIN32	
int execute_command_thread(void *arg){
	struct params_thread *par = (struct params_thread*) arg;
	char buff[BUFF_READ];
	
	// ESEGUO IL COMANDO E REDIRIGO OUTPUT SU PIPE
	char cmd[strlen(par->cmd_name)+10];
	cmd[0]='\0';
	strcat(cmd, par->cmd_name);
	strcat(cmd, " 2>&1");
	
	FILE *pipe_stdout_cmd = popen(cmd, "r");
	if(pipe_stdout_cmd == NULL){
		print_my_error("functionality.execute_command_thread");
		return EXIT_FAILURE;
	}
	
	// LEGGO OUTPUT DEL COMANDO
	while(fgets(buff, sizeof(buff), pipe_stdout_cmd) != NULL){
		if(concatenate_string(par->p_output_cmd, par->output_len, par->output_cmd_size, buff, strlen(buff))){
			print_my_error("functionality.execute_command_thread.concatenate_string");
			return EXIT_FAILURE;
		}
	}
	
	// CONTROLLO ERRORI SU fgets
	if( ferror(pipe_stdout_cmd) ){
		print_my_error("functionality.execute_command_thread.fgets");
		return EXIT_FAILURE;
	}
		
	// CHIUDO PIPE
	if( pclose(pipe_stdout_cmd) ) 
		print_my_error("functionality.execute_command_thread.pclose");

	// SEGNALO COMANDO ESEGUITO
	if( pthread_cond_signal(par->cond_vrb)){
		print_my_error("functionality.execute_command_thread.pthread_cond_signal");
		return EXIT_FAILURE;
	}
		
	return EXIT_SUCCESS;
}
	

#else

/*
 * Thread WIN che lancia il processo per l'esecuzione vera e propria del comando
 */

DWORD WINAPI execute_command_thread(LPVOID params){
    LPCSTR cmdPath = "C:\\Windows\\System32\\cmd.exe";											// cmd.exe path						
	
	// RISULTATO DI RITORNO DEL THREAD
	DWORD res = EXIT_SUCCESS;

	// RICAVO PARAMETRI 
	CMD cmd_name = ((struct params_thread *)params)->cmd_name;							
	char **p_output_cmd = ((struct params_thread *)params)->p_output_cmd;					// puntatore al puntantore del buffer di output
	size_t *bytes_written_out_buff = ((struct params_thread *)params)->output_len;    		// byte scritti nel buffer di output	
	size_t *output_buff_size = ((struct params_thread *)params)->output_cmd_size;
	HANDLE event_0 = ((struct params_thread *)params)->h_event;

	// STRUTTURE DEL PROCESSO 'CMD.EXE' CHE VERRA CREATO
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;
	
	// AZZERO MEMORIA IN STARTUP_INFO E PROCESS_INFO
	ZeroMemory(&process_info,sizeof(PROCESS_INFORMATION));
	ZeroMemory(&startup_info, sizeof(STARTUPINFO));
	
	// IMPOSTO IL FLAG A TRUE COSI GLI HANDLE DELLA PIPE POTRANNO ESSERE EREDITATI
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 									// grandezza struttura
 	saAttr.bInheritHandle = TRUE; 													
   	saAttr.lpSecurityDescriptor = NULL;
	
	// CREO LA NAMED-PIPE, DI TIPO BYTE_TYPE, WAIT, OUTBOUND.
	char id[13];
	if(!get_unique_thread_id_string(id)){
		print_my_error("functionality.get_unique_thread_id_string.CONVERSION");
		SetEvent(event_0);
		ExitThread(EXIT_FAILURE);
	}

	char pname[strlen(PIPECMD_BASENAME) + sizeof(id)];
	pname[0] = '\0';
	strcat(pname, PIPECMD_BASENAME);
	strcat(pname, id);

	HANDLE nPipe_sv = CreateNamedPipeA(pname,										// creo named-pipe, lato server
                    PIPE_ACCESS_OUTBOUND,
                    0,																// default di tipo BYTE_MODE
                    2, PIPE_SIZE,													// numero massimo di handle: 2
					 PIPE_SIZE, 
					0,&saAttr);

	// CONTROLLO SE LA CREAZIONE SIA ANDATA A BUON FINE
	if(nPipe_sv == INVALID_HANDLE_VALUE){
		print_my_error("functionality.execute_command_thread.CreateNamedPipeA");
		res = EXIT_FAILURE;
	}
	
	 // APRO NAMED PIPE LATO CLIENT(QUESTO THREAD)
    HANDLE nPipe_cl = CreateFile(pname, 
								GENERIC_READ|FILE_WRITE_ATTRIBUTES					// il client puo solo leggere la pipe, ma modificare gli attrivuti dell'handle
								, 0, NULL, OPEN_EXISTING 	
								,FILE_FLAG_OVERLAPPED, NULL);						// di default overlapped e' disabilitato

	// CONTROLLO SE L'APERTURA DEL CLIENT-END SIA ANDATA A BUON FINE
	if(nPipe_cl == INVALID_HANDLE_VALUE){
		print_my_error("functionality.execute_command_thread.CreateFile.CREAZIONE_CLIENT_END_NPIPE");
		res = EXIT_FAILURE;
	}

	// CAMBIO WAIT-MODE DELL'HANDLE LATO-CLIENT IN NO-WAIT
	DWORD mode = PIPE_READMODE_BYTE|PIPE_NOWAIT;
	if(!SetNamedPipeHandleState(nPipe_cl, &mode, NULL, NULL) ){
		print_my_error("functionality.execute_command_thread.SetNamedPipeHandleState");
		res = EXIT_FAILURE;
	}
	
	// IMPOSTO ATTRIBUTI DI STARTUP_INFO, PER ASSEGNARE LA NPIPE ALLO STDOUT DEL CMD
	startup_info.cb = sizeof(STARTUPINFO);											// Grandezza struttura
	startup_info.dwFlags |= STARTF_USESTDHANDLES;									// Considero validi i parametri sullo std_in|out|err
	startup_info.hStdOutput = nPipe_sv;
	startup_info.hStdError = nPipe_sv;
	startup_info.hStdInput = NULL;													// Std_in di default
	
	// CREO PROCESSO CMD.EXE 
	char *cmd_flags = my_strcat("/C ", cmd_name);									// Argomenti dati al cmd, con '/C' esegue il comando e termina
	if(CreateProcessA(cmdPath,cmd_flags, NULL, NULL									// Processo del cmd.exe
			,TRUE, 0, NULL, NULL, &startup_info, &process_info) == 0){	
		print_my_error("functionality.execute_command_thread.CreateProcess");
		res = EXIT_FAILURE;				
	}

	// INIZIALIAZZO BUFFER E VARIABILI PER LA READFILE
	char read_buff[BUFF_READ];
	DWORD nByteRead;
	DWORD extCode_cmd;
	BOOL read;
	BOOL getExcd;

    // LEGGO OUTPUT DEL CMD
	while(1){
		if(res == EXIT_FAILURE)
			break;
		if(!(getExcd = GetExitCodeProcess(process_info.hProcess, &extCode_cmd))){
			// SE OCCORSO ERRORE IN GetExitCodeProcess
		 	print_my_error("functionality.execute_command_thread.GetExitCodeProcess");
            res = EXIT_FAILURE;
            break;       
		}
		if(read = ReadFile(nPipe_cl, read_buff, BUFF_READ, &nByteRead, NULL)){
            if(concatenate_string(p_output_cmd, bytes_written_out_buff,output_buff_size,read_buff,(size_t)nByteRead))
				print_my_error("functionality.execute_command_thread.concatenate_string");
        }
		if(getExcd){																			// 
            if(extCode_cmd != STILL_ACTIVE){													// se processo terminato
                if(!read){																		// e read fallita per 
                    if(GetLastError() == ERROR_NO_DATA){										// pipe vuota allora output terminato
                        break;																	// a e l'output e' stato interamente consumato
                    }
                    else{
                        print_my_error("functionality.execute_command_thread.ReadFile");
                        res = EXIT_FAILURE;
                        break;
                    }
                }
            }
        }
    }

	// SEGNALO OUTPUT PRONTO
	if(!SetEvent(event_0)){
		print_my_error("functionality.execute_command_thread.SetEvent");
		res = EXIT_FAILURE;
	}

	// CHIUDO L'HANDLE LATO READ DELLE PIPE CREATA
	CloseHandle(nPipe_sv);
	CloseHandle(nPipe_cl);

	free(cmd_flags);
	
    ExitThread(res);
}

#endif
