/*
 *  Questo modulo si occupa di trasferire le impostazioni di configurazione,
 *  presenti in un dato file con estensione .config, in variabili.
 *  
 *  
 *  Created by 
 *  Mattia Paolacci 
 */ 

#include "manage_configuration.h"
#include "list.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#define BUFFSIZE 32
#define DEFAULT_PLAIN_PORT 8080

// MESSAGGI ERRORE STANDARD
#define SYNTAX_ERR "Errore nel file di configurazione: modalita' di avvio non valida.\n"
#define SAME_PORT_ERR "Errore di configurazione: le porte di ascolto 'ENCHIPHER' e 'PLAIN' sono uguali.\n"

void init_config_struct(struct config *c){
	c->C_DIR_FILE_LOG = NULL;
	c->C_PATH_PASSWD = NULL;
    c->C_MODE_THREAD = 0;
    c->C_PROCS_THREAD_ENCI = 0;
	c->C_MODE_PROCESS = 0;
   	c->C_PORT_ENCIPHER = 0;
   	c->C_PORT_PLAIN = 0;
   	c->C_LSTN_QUEUE_LEN = 0;
}

void cleanup_config_struct(struct config *c){
    free(c->C_PATH_PASSWD);
	free(c->C_DIR_FILE_LOG);
    init_config_struct(c);
}

int get_configuration(struct config *c){
    char read_buff[BUFFSIZE];
    
    // CAMPI PER LA STRINGA DEL CONTENUTO DEL FILE .conf
    char *text = NULL;
    size_t space_alloc = 0;
    size_t len_text = 0;

    // WINDOWS OPEN
    #ifdef _WIN32
    HANDLE file_conf_h = CreateFile(c->C_NAMEPATH_FILE_CONF,GENERIC_READ,0,NULL,                 // Il file puo essere aperto
									OPEN_EXISTING,0,NULL);                                       //     da un solo processo/thread.
    if(file_conf_h == INVALID_HANDLE_VALUE){													// Controllo se open andata bene
		print_my_error("manage_configuration.get_configuration.CreateFile");
		return GENERIC_INT_ERROR;
	}
	DWORD byte_read;
	
    
    // UNIX OPEN ESCLUSIVA
	#else
	ssize_t byte_read;																					// numero di byte letti all'i-esimo ciclo
	int file_conf_fd = open(c->C_NAMEPATH_FILE_CONF, O_RDONLY|O_EXLOCK);													
	if(file_conf_fd == -1){
		print_my_error("manage_configuration.get_configuration.open");
		return GENERIC_INT_ERROR;
	}
    #endif

    // LEGGO FILE DI CONFIGURAZIONE
    do{
        // WINDOWS READ
        #ifdef _WIN32
        if(ReadFile(file_conf_h,read_buff,BUFFSIZE,&byte_read,NULL)==0){
			print_my_error("manage_configuration.get_configuration.ReadFile");
			free(text);
            CloseHandle(file_conf_h);
            return GENERIC_INT_ERROR;
		}

        // UNIX READ
        #else 
        byte_read = read(file_conf_fd, read_buff, BUFFSIZE);
		if (byte_read == -1) {
			print_my_error("manage_configuration.get_configuration.ReadFile");
			free(text);
			close(file_conf_fd);
			return GENERIC_INT_ERROR;
		}
        #endif
        
        // WIN-UNIX, CONCATENO IL BUFFER ALLA STRINGA DEL FILE
        if(concatenate_string(&text, &len_text, &space_alloc, read_buff, byte_read)){
            print_my_error("manage_configuration.get_configuration.concatenate_string");
            free(text);
            #ifdef _WIN32
            CloseHandle(file_conf_h);
            #else
            close(file_conf_fd);
            #endif
            return GENERIC_INT_ERROR;
        }
        
    }while(byte_read>0);

    // CHIUDO FILE HANDLE/FILE DESCRIPTOR
    #ifdef _WIN32
        CloseHandle(file_conf_h);
    #else
        close(file_conf_fd);
    #endif
    
    // LISTA CONFIGURAZIONI: i:NOME_CONF, i+1:VALORE_CONF
    list_t *confs = split_by_token(text, len_text, '=', '=');
    
    int i=0;
    int res=0;
    
    // RIEMPIMENTO DELLA STRUTTURA struct config
    while(i<(confs->len-1)){
        char *name_conf = get_element_from_list(confs, i);
        if(!strcmp(name_conf, PATH_PASSWD)){
            c->C_PATH_PASSWD = get_element_from_list(confs,i+1);
            confs->array[i+1] = NULL;
        }
        else if(!strcmp(name_conf, DIR_FILE_LOG)){
            c->C_DIR_FILE_LOG = get_element_from_list(confs,i+1);
            confs->array[i+1] = NULL;
        }
        else if(!strcmp(name_conf, MODE_THREAD))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_MODE_THREAD)));
        else if(!strcmp(name_conf, MODE_PROCESS))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_MODE_PROCESS)));
        else if(!strcmp(name_conf, PORT_ENCIPHER))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_PORT_ENCIPHER)));
        else if(!strcmp(name_conf, PORT_PLAIN))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_PORT_PLAIN)));
        else if(!strcmp(name_conf, LISTEN_QUEUE_LEN))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_LSTN_QUEUE_LEN)));
        else if(!strcmp(name_conf, PROCS_THREAD_ENCI))
            res |= (1 != sscanf(get_element_from_list(confs,i+1), "%hi", &(c->C_PROCS_THREAD_ENCI)));
        i+=2;
    }

    // DISTRUGGO LISTA
    dealloc_array_of_char_pointer((void**)confs->array,confs->len);
    destroy_list(confs);
    free(text);

    // IN CASO DI ERRORE DEALLOCO VALORI DI TIPO STRINGA, PRECEDENTEMENTE CONSERVATI
    if(res){
		print_my_error("manage_configuration.get_configuration: ERRORE IN SCANF PARAMETRI");
		cleanup_config_struct(c);
		return GENERIC_INT_ERROR;
    }
    return 0;

}

int check_configuration(struct config *conf){
	// CONTROLLO SE LA MODALITA SCELTA SIA UNIVOCA
	if(conf->C_MODE_THREAD>0 && conf->C_MODE_PROCESS>0){
		printf(SYNTAX_ERR);
		return GENERIC_INT_ERROR;
	}

	if(!conf->C_MODE_PROCESS && !conf->C_MODE_THREAD){
		printf(SYNTAX_ERR);
		return GENERIC_INT_ERROR;
	}

    if(conf->C_PORT_PLAIN == 0)
        conf->C_PORT_PLAIN = DEFAULT_PLAIN_PORT;

	// CONTROLLO SE LE PORTE DI RITORNO_CIFRATO E RITORNO_INCHIARO SIANO UGUALI
	if(conf->C_PORT_ENCIPHER == conf->C_PORT_PLAIN){
		printf(SAME_PORT_ERR);
		return GENERIC_INT_ERROR;
	}
	
	// CONTROLLO SE PRESENTE IL NOME DEL FILE DI CONFIGURAZIONE
	if(conf->C_NAMEPATH_FILE_CONF == NULL){
		print_my_error("server.check_configuration : NOME FILE DI CONFIGURAZIONE NULL");
		return GENERIC_INT_ERROR;
	}
	return 0;
}