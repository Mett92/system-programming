/*
 *  Questo modulo si occupa di trasferire le impostazioni di configurazione,
 *  presenti in un dato file con estensione .config, in variabili.
 *  
 *  
 *  Created by 
 *  Mattia Paolacci 
 */ 
#ifndef _MANAGE_CONFIGURATION_H_
#define _MANAGE_CONFIGURATION_H_
#include "utility.h"

// NOMI COSTANTI PRESENTI ALL'INTERNO DEL FILE DI CONFIGURAZIONE
// SE VIENE AGGIUNTO UN PARMETRO NEL FILE DI CONFIGURZAZIONE AGGIUNGERLO ANCHE IN:
//      -struct config  
//      -in get_configuration
//      -in #define
//      -nella funzione che controlla errori (se la variabile è stringa)

#define PATH_PASSWD "PATH.PASSWD"
#define MODE_THREAD "MODE.THREAD"
#define MODE_PROCESS "MODE.PROCESS"
#define PROCS_THREAD_ENCI "PROCS.THREAD.ENCI"		// numero di processi/thread (a seconda della modalita) creati in ascolto sulla porta che cifra
#define PORT_ENCIPHER "PORT.ENCIPHER"
#define PORT_PLAIN "PORT.PLAIN"
#define LISTEN_QUEUE_LEN "LISTEN.QUEUE.LEN"
#define DIR_FILE_LOG "DIR.FILE.LOG"                 //conterra il path della directory dove salvare il file di log


struct config{
	char *C_NAMEPATH_FILE_CONF;						// deallocare
	char *C_PATH_PASSWD;                            // deallocare
	char *C_DIR_FILE_LOG;                           // deallocare
	short C_MODE_THREAD;
	short C_MODE_PROCESS;
	short C_PROCS_THREAD_ENCI;						// processi/thread in ascolto sulla porta che cifra
   	short C_PORT_ENCIPHER;
   	short C_PORT_PLAIN;
   	short C_LSTN_QUEUE_LEN;
};

void init_config_struct(struct config *c);

/*
 * 	Libera memoria allocata in config e richiama init_config_struct
 * 
 *  NOTA: In caso vengano aggiunti parametri alla struct in cui venisse allocata
 *  memoria sull'heap, inserire in questa funzione una chiamata a free.
 */
void cleanup_config_struct(struct config *c);

/*
 *  Completa la struttura puntata con i parametri di configurazione forniti all'interno del file "file_conf".
 */
int get_configuration(struct config *c);

/*
 * 	Controlla che i parametri nel file di configurazione rispettino
 * 	i vincoli richiesti
 */
int check_configuration(struct config *conf);

#endif