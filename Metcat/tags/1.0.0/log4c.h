/*
 *  Questo modulo si occupa di scrivere i log, in un certo formato sul file.
 *  
 *  
 *  Created by 
 *  Mattia Paolacci 
 */ 

#ifndef _LOG4C_H_
#define _LOG4C_H_
#include "http_utility.h"
#include "functionality.h"

/*
 *  Inizializza l'ambiente di log:
 *  Se non esiste crea il file di log col nome ...conf.path/GGMM_HHMMSS.LOG
 */
int init_log_environment();

/*
 *  Appende al file di log odierno la log_phrase, passata in input.
 */
int append_log(char *log_phrase, size_t len_log);

/*
 *  Appende al file di log odireno il log nel formato common_log_format
 */
int append_common_log_format(http_request_t *cl_req, http_response_t *cl_resp, MODE flag_cyp);

#endif