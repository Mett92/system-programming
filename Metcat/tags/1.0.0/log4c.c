/*
 *  Questo modulo si occupa di scrivere i log, in un certo formato sul file.
 *  
 *  
 *  Created by 
 *  Mattia Paolacci 
 */ 
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif
#include "log4c.h"
#include "manage_configuration.h"
#include "utility.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif
#define WELCOME_PHRASE "***************************************************** SESSION STARTED AT %H:%M:%S *****************************************************"
#define TIME_CLF "%d/%b/%Y:%H:%M:%S %z"                     //formato del tempo nel common log format
#define MAX_LEN_LOG 512
#define BUFF_LOCALTIME_LEN 128
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 256
#endif

extern struct config conf;
char name_file_log[MAX_PATH_LEN];


#ifdef _WIN32
int append_log(char *log_phrase, size_t len_log){
    // APRE IL FILE
    HANDLE file_log_h = CreateFileA(name_file_log, GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,                        
									OPEN_EXISTING,0,NULL);                                        
    if(file_log_h == INVALID_HANDLE_VALUE){													
		print_my_error("log4c.append_log.CreateFile");
		return GENERIC_INT_ERROR;
	}
    // SE IL FILE GIA ESISTE, VIENE SETTATO UN ERRORE, QUINDI SETTO LASTERROR A 0.
    SetLastError(0);                                                        

    // MI POSIZIONO ALLA FINE DEL FILE
    SetFilePointer(file_log_h, 0, NULL, SEEK_END);

    // STRUTTURA UTILE PER IL LOCK_WIN
    OVERLAPPED ovllp_lock;
    ovllp_lock.Offset = 0;
    ovllp_lock.OffsetHigh = 0;
    ovllp_lock.hEvent = NULL;
    
    // PRENDO IL LOCK 
    if(!LockFileEx(file_log_h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ovllp_lock)){
        print_my_error("log4c.append_log.LockFileEx");
        CloseHandle(file_log_h);
        return GENERIC_INT_ERROR;
    }
    
    // APPENDO IL LOG
    DWORD byte_wr;
    int res = 0;
    char loggone[len_log];
    strcpy(loggone, log_phrase);
    if(res |= !WriteFile(file_log_h, log_phrase, len_log, &byte_wr, NULL))
        print_my_error("log4c.append_log.WriteFile");
    if(res |= !WriteFile(file_log_h, NEWLINE, strlen(NEWLINE), &byte_wr, NULL))
        print_my_error("log4c.append_log.WriteFile");

    // LASCIA LOCK
    if(!UnlockFile(file_log_h, 0, 0,MAXDWORD, MAXDWORD)){
        print_my_error("log4c.append_log.UnlockFile");
        res |= 1;
    }
    
    // CHIUDE IL FILE
    if(!CloseHandle(file_log_h))
        print_my_error("log4c.append_log.CloseHandle");
    
    if(res)
        return GENERIC_INT_ERROR;
    return 0;

}


#else
int append_log(char *log_phrase, size_t len_log){
    // PRENDE L'ORARIO E CONCATENO COSI: conf.C_DIR_FILE_LOG/GG_MM.log
	
    // APRE IL FILE
	int file_log_fd = open(name_file_log, O_WRONLY | O_APPEND);														
	if(file_log_fd == -1){
		print_my_error("log4c.append_log.open");
		return GENERIC_INT_ERROR;
	}

    // PRENDE IL LOCK SU FILE
    if(lockf(file_log_fd, F_LOCK, 0)){
        print_my_error("log4c.append_log.lockf.LOCK");
        return GENERIC_INT_ERROR;
    }

	int res = 0;
	// APPENDO IL LOG
	res |= write(file_log_fd, log_phrase, len_log) == GENERIC_INT_ERROR;
	res |= write(file_log_fd, NEWLINE, strlen(NEWLINE)) == GENERIC_INT_ERROR;
	
	if(res){
		print_my_error("log4c.append_log.write");
		return GENERIC_INT_ERROR;
	}

    // RILASCIA LOCK
    if(lockf(file_log_fd, F_ULOCK, 0)){
        print_my_error("log4c.append_log.lockf.UNLOCK");
        return GENERIC_INT_ERROR;
    }

    // CHIUDO FILE DESCRIPTOR
    if(close(file_log_fd))
        print_my_error("log4c.append_log.close");

    return 0;
}
#endif

// testare la parte unix
int init_log_environment(){
    // RICAVO TEMPO E FORMATTO IN STRINGA
    struct tm info;
    if(get_local_time_now(&info)){
        print_my_error("log4c.init_log_environment.get_local_time_now");
        return GENERIC_INT_ERROR;
    }
    size_t len_buff = strlen(WELCOME_PHRASE)+4;
    char init_phrase_buff[len_buff];
    strftime(init_phrase_buff,len_buff,WELCOME_PHRASE, &info);

    // INIZIALIZZO IL NOME DEL FILE
    name_file_log[0]='\0';
    strcat(name_file_log, conf.C_DIR_FILE_LOG);
    if(name_file_log[strlen(name_file_log)-1]!='/')    
        strcat(name_file_log, "/");
    sprintf(name_file_log+strlen(name_file_log), "%d%d.log", info.tm_mday, info.tm_mon+1);             // Formatto il nome del file
	
    // APRE/CREA FILE DI LOG ODIERNO WIN
    #ifdef _WIN32
    HANDLE file_log_h = CreateFileA(name_file_log, GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);                                        
    if(file_log_h == INVALID_HANDLE_VALUE){													
		print_my_error("log4c.init_log_environment.CreateFile");
		return GENERIC_INT_ERROR;
	}
    SetLastError(0);
    CloseHandle(file_log_h);
    
    // APRE/CREA FILE DI LOG ODIERNO UNIX
    #else
    int file_log_fd = open(name_file_log, O_CREAT,S_IRWXU | S_IRGRP | S_IROTH);							// Permessi rwxr--r--
	if(file_log_fd == -1){
		print_my_error("log4c.init_log_environment.open");
		return GENERIC_INT_ERROR;
	}
    close(file_log_fd);
    #endif

    // APPENDE FRASE DI WELCOME
    append_log(init_phrase_buff, strlen(init_phrase_buff));

    return 0;
}

int append_common_log_format(http_request_t *cl_req, http_response_t *cl_resp, MODE flag_cyp){
    // BUFFER PER IL LOG
    char log_buff[MAX_LEN_LOG];
    
    // PRENDE IL LOCAL TIME 
    struct tm info_local;
    if(get_local_time_now(&info_local)){
        print_my_error("log4c.append_users_session_log.get_local_time_now");
        return GENERIC_INT_ERROR;
    }
    
    // INSERISCO IL TEMPO FORMATTATO NEL BUFFER
    char time_buff[BUFF_LOCALTIME_LEN];
    if(strftime(time_buff,BUFF_LOCALTIME_LEN,TIME_CLF, &info_local)>BUFF_LOCALTIME_LEN){
        print_my_error("log4c.append_common_log_format.strftime: \"BUFFER LOCALTIME TROPPO CORTO\"");
        return GENERIC_INT_ERROR;
    }
    
    // CONVERTO INDIRZZO IP IN STRINGA
    char ip_string[16];
    char nport[24];
    ip_to_string(&cl_req->cl_addr, ip_string);
    nport_to_string(&cl_req->cl_addr, nport);
	
    // FORMATTO IL BUFFER DI LOG
    if(sprintf(log_buff, "%s %hi,%s %s [%s] \"%s %s %s\" %s %lu%s", 
			   ip_string, flag_cyp ? conf.C_PORT_ENCIPHER : conf.C_PORT_PLAIN,
			   nport, cl_req->username, time_buff
                , cl_req->method == NULL ? "-" : cl_req->method
                , cl_req->uri == NULL ? "-" : cl_req->uri
                , cl_req->http_vers == NULL ? "-" : cl_req->http_vers
                , cl_resp->status_code, cl_resp->content_length_uint, NEWLINE) > MAX_LEN_LOG){
        print_my_error("log4c.append_common_log_format.sprintf: \"BUFFER DI LOG TROPPO CORTO\"");
        return GENERIC_INT_ERROR;
    }
    
    return append_log(log_buff, strlen(log_buff));
}