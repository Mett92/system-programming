/*
 * utilityFunction.c
 * ServerApp
 * 
 * Gestisce la stampa a degli errori
 * 
 *  Created by Mattia Paolacci
 */

#ifdef _WIN32
	#include <malloc.h>
	#include <stddef.h>
	#include <windows.h>
	#include <shlwapi.h>
	#include <winsock2.h>
#else
	#include <syslog.h>
	#include <stdarg.h>
	#include <errno.h>
	#include <string.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <sys/stat.h>
	#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>

//Project files
#include "utility.h"
#include "list.h"

#define	ERR_MSG_LEN 512
#define	WIN_BASEPATH "C:"
#define MYWORD unsigned long long 			/* Parola di riferimento per la funzione di concatenazione */

#ifdef _WIN32
// MUTEX PER LA FUNZIONE LOCALTIME IN WINDOWS
CRITICAL_SECTION mutex_localtime;

void init_utility_mutex(){
	InitializeCriticalSection(&mutex_localtime);
}

// Restituisce 0 se tutto ok, 1 altrimenti
// buff di grandezza almeno 12
int get_unique_thread_id_string(char *buf){
	return sprintf(buf, "%lu", GetCurrentThreadId());
}
#endif

void print_my_error(char *stringErr){
	#ifdef _WIN32
		errno = GetLastError();
	if(errno != 0)
		fprintf(stderr,"%s : %d : %s\n", stringErr,errno, strerror(errno));
	else 
		fprintf(stderr, "%s\n", stringErr);
	#else
	if(errno != 0)
		syslog(LOG_ERR, "%s : %d : %s\n", stringErr,errno, strerror(errno));
	else 
		syslog(LOG_ERR, "%s\n", stringErr);
	#endif
	errno = 0; /* reset */
}

void copy_str_in_arr(char *str, char *arr){
    int i;
    size_t len_str = strlen(str);
    for(i=0; i<len_str; i++){
        arr[i] = str[i];
    }
    arr[len_str] ='\0';
}

int strcmp_da_a(char *str, char *check, int da, int a){
    char *substr = strcpy_da_a(str,da,a);
    int res = strcmp(substr,check);
    free(substr);
    return res;
}

/*
 *  Disallocare memoria puntata, ritornata
 */
char *strcpy_da_a(char *str, size_t da, size_t a){
    size_t len = (a+1)-da + 1;  // +1 per il '\0'
    char *str_ret;
    str_ret = (char *)malloc(sizeof(char)*len);
    if(str_ret == NULL){
        print_my_error("moduleUtility.strcpy_da_a.malloc");
        return NULL;
    }
    int i;
    for(i=0; i<(len-1); i++){   //-1 perche considero il posto di '\0'
        str_ret[i] = str[da+i];
    }
    str_ret[len-1] = '\0';
    return str_ret;
}


list_t *split_by_token(char *str, size_t len, char token, char token_2){
	int res = 0;
    list_t *strgs;
    strgs = get_new_list();
    if(strgs == NULL){
        print_my_error("moduleUtility.split_by_token.get_new_list");
        return NULL;
    }
    int i, j;
    int da = 0;
    for(i=0; i<len ;i++){
        if(!(str[da]>='!' && str[da]<='~')){
            da++;
            continue;
        }
        else if(str[i] == token || str[i] == token_2 || !(str[i]>='!' && str[i]<='~') ){           // splitta automaticamente per caratteri non stampabili
            if(da == i){                                                                       // se il token è in posizione da
                da++;
                continue;
            }
            else{
                int a = i-1;
                while(!(str[a]>='!' && str[a]<='~'))
                    a--;
                res |= append_to_list(strgs,strcpy_da_a(str,da,a));
                da = i+1;
            }
        }
        else if(i == len-1){  											                                		  			// se i è l'ultima lettera ed e' un carattere stampabile non token
            res |= append_to_list(strgs, strcpy_da_a(str, da, i));
        }
    }
    if(res){                                                                                    // in caso di errore nelle append
        print_my_error("utility.split_by_token.append_to_list");
        dealloc_array_of_char_pointer((void**)strgs->array,strgs->len);
        destroy_list(strgs);
        return NULL;
    }
    return strgs;
}

int find_last_newline(char *str, size_t len){
    int i;
    int last = -1;
    for(i=0; i<len; i++)
		if(str[i] == '\n')
			if(str[i-1] == '\r')
            	last = i-1;
			else
				last = i;
    return last;
}

/* 	
 *	Copia un buffer da src a dest assume che il modulo della divisione 
 *	tra len_src e len(MYWORD) sia uguale a 0, cosi da evitare di deferenziare
 * 	all'esterno di dest.
 */
void cpy_buf(char *dest, const char *src, size_t len_src){
    int i;
    for(i = 0; i < len_src; i += sizeof(MYWORD)){
        *( (MYWORD *)(dest + i) ) = *( (MYWORD *)(src + i) );
    }
}
 
int concatenate_string(char** point_to_buff, size_t *used_space, size_t *size_buff, char *str, size_t len_str){
    int i;
    size_t len_occ = *used_space + len_str;                                 /* spazio necesssario */
    if(*size_buff > (len_occ + sizeof(MYWORD)+1) ){                         /* Se lo spazio disponibile nel buffer e' sufficiente */
        cpy_buf(*point_to_buff + *used_space, str, len_str);
        *used_space = len_occ;                                				/* aggiorno lo spazio usato in *point_to_buff */
        return 0;
    }
    else{                                                                   /* Altrimenti */
        size_t resto = len_str % sizeof(MYWORD);
        size_t mod = (resto == 0) ? 0 : (sizeof(MYWORD) - resto);             /* byte da aggiungere affinche la lunghezza sia divisibile per len(MYWORD) */ 
        size_t tmp_size = ((*size_buff + len_str + mod)*2);                 /* Nuova grandezza del buffer con coefficiente 2*/
        
        char *tmp;                                                      
        if(*point_to_buff == NULL){                                         /* In caso che il puntatore e' null lo devo inizializzare */
            tmp = (char*)malloc(tmp_size);
        }
        else
			tmp = (char*)realloc(*point_to_buff, tmp_size);
		if(tmp == NULL){
			print_my_error("utility.concatenate_string.realloc(malloc)");
			return -1;
		}
        
        cpy_buf(tmp + *used_space, str, len_str);                     		/* copio il buffer */
        
        /* aggiorno variabili */
        *size_buff = tmp_size; 
        *used_space = len_occ;                                
        *point_to_buff = tmp;
        return 0;
    }
}

/* Sostituisce sub a tok nella stringa str */
void replace_token(char *str, size_t len_str, char tok, char sub){
	int i;
	for (i=0; i<len_str; i++){
		if(str[i] == tok)
			str[i]=sub;
	}
}

char *my_strcat(char *str1, char *str2){
    int i;
    size_t lenf = strlen(str1) + strlen(str2) + 1;                 // lunghezza di str1_str2 + terminatore
    char *str1_str2 = (char *)malloc(sizeof(char)*lenf);
    for(i=0; i<strlen(str1); i++){
        str1_str2[i] = str1[i];
    }
    for(i; i<(lenf-1); i++){
        str1_str2[i] = str2[i-strlen(str1)];
    }
    str1_str2[lenf-1] = '\0';
    return str1_str2;
}

void dealloc_array_of_char_pointer(void **arr, size_t len){
    int i;
    for(i=0; i<len; i++)
        free(arr[i]);
}

WIN_PATH convert_uri_to_winpath(URI uri){
    WIN_PATH path = NULL;																
	size_t space_allocated = 0;
	size_t len_path = 0;																// lunghezza della stringa path
	
    if(concatenate_string(&path, &len_path, &space_allocated, 						// aggiungo win basepath: "C:"
		WIN_BASEPATH, strlen(WIN_BASEPATH))){				
		print_my_error("utility.convert_uri_to_winpath.concatenate_string");
        return GENERIC_NULL_ERROR;
    }
    
	if(concatenate_string(&path, &len_path, &space_allocated, 
		uri, strlen(uri))){
		print_my_error("utility.convert_uri_to_winpath.concatenate_string");
        return GENERIC_NULL_ERROR;
    }
	path[len_path] = '\0';															// path diventa cosi una stringa
    int i;
    for(i=0; i<strlen(path); i++)
        if(path[i] == '/')
            path[i] = '\\';                                                         // converto i forward-slash in back-slash
    return path;
}

// promiscua
URI_TYPE get_uri_type(URI uri, PATH *path){
	
	//UNIX + WINDOWS
	PATH p;
	
	// CONTROLLO SE L'URI CORRISPONDA AD UNA RICHIESTA DI COMANDO
	CMD cmd_name = is_command(uri);
	if(cmd_name != NULL){
		if (cmd_name == (CMD) -1)
			return URI_IS_INVALID_CMD;
		
		//ELSE
		*path = cmd_name;
		return URI_IS_CMD;
	}

	#ifdef _WIN32
	// WINDOWS
	
	// CONVERTO URI TO WINPATH
	p = convert_uri_to_winpath(uri);
	*path = p;

	// CONTROLLO ERRORI
	if(*path == NULL){
		print_my_error("utility.get_uri_type.convert_uri_to_winpath");
		return GENERIC_INT_ERROR;
	}

	// CONTROLLO CHE SIA DIRECTORY
	if(PathIsDirectoryA(p))
		return URI_IS_DIR;
	
	// CONTROLLO CHE SIA UN FILE (basta che esista, dato che ho escluso le directory)
	if(PathFileExistsA(p))
		return URI_IS_FILE;
	
	// UNIX
	#else
	p = strcpy_da_a(uri, 0, strlen(uri));
	if(p == NULL){
		print_my_error("utility.get_uri_type.strcpy_da_a");
		return GENERIC_INT_ERROR;
	}
	*path = p;
	struct stat path_stat;										// Struttura per stat
	if(stat(p, &path_stat)){
		if(errno==ENOENT){
			return INVALID_URI;
		}
		else{
			print_my_error("utility.get_uri_type.stat");
			return GENERIC_INT_ERROR;
		}
	}
		
	// CONTROLLO CHE SIA UN FILE
	if(S_ISREG(path_stat.st_mode))
		return URI_IS_FILE;
	
	// CONTROLLO SE E' UNA DIRECTORY
	if(S_ISDIR(path_stat.st_mode))
		return URI_IS_DIR;
	#endif

	// OPPURE IL FILE NON ESISTE
	return INVALID_URI;
}

// Se ritorna  (char *) -1 allora non e' stato fornito nessun comando  
CMD is_command(URI uri){
	CMD cmd = NULL;
	list_t *list = split_by_token(uri,strlen(uri),'/','/');
	if (list->len >= 1){
		if( (strcmp(get_element_from_list(list,0), KEY_CMD_REQ) == 0) && (list->len >1) ){            		// Controllo che uri richieda esecuzione conmando
			cmd = get_element_from_list(list,1);									// nome del comando
			list->array[1] = NULL;												// per mantenere allocata la stringa
		}
		else if((strcmp(get_element_from_list(list,0), KEY_CMD_REQ) == 0) && (list->len == 1) )
			cmd = (CMD) -1;
	}
	dealloc_array_of_char_pointer((void **)list->array, list->len);
	destroy_list(list);
	return cmd;
}

unsigned int ip_to_uint(struct sockaddr *address){
    struct sockaddr_in *s_addr_in;
	s_addr_in = (struct sockaddr_in *)address;
	
	#ifdef _WIN32
	unsigned int b1 = 0;
	unsigned int b2 = 0;
	unsigned int b3 = 0;
	unsigned int b4 = 0;
	
	b1 |= s_addr_in->sin_addr.S_un.S_un_b.s_b1;
	b2 |= s_addr_in->sin_addr.S_un.S_un_b.s_b2;
	b3 |= s_addr_in->sin_addr.S_un.S_un_b.s_b3;
	b4 |= s_addr_in->sin_addr.S_un.S_un_b.s_b4;
	
	b1<<=24;
	b2 <<=16;
	b3 <<=8;
	return b1 | b2 | b3 | b4;
	#else
	
	return s_addr_in->sin_addr.s_addr;
	#endif
}

int get_local_time_now(struct tm *info_local){
	time_t rawtime;
	time(&rawtime);
	#ifdef _WIN32
	
	EnterCriticalSection(&mutex_localtime);
	*info_local = *localtime(&rawtime);
	LeaveCriticalSection(&mutex_localtime);
	
	#else
	localtime_r(&rawtime, info_local);
	#endif
	
	return 0;
}

void nport_to_string(struct sockaddr *address, char *to_string){
	struct sockaddr_in *s_addr_in;
	s_addr_in = (struct sockaddr_in *)address;
	sprintf(to_string, "%hu", ntohs(s_addr_in->sin_port));
}

void ip_to_string(struct sockaddr *address, char *to_string){
	struct sockaddr_in *s_addr_in;
	s_addr_in = (struct sockaddr_in *)address;
	
	#ifdef _WIN32
	unsigned char b1 = 0;
	unsigned char b2 = 0;
	unsigned char b3 = 0;
	unsigned char b4 = 0;
	
	b1 |= s_addr_in->sin_addr.S_un.S_un_b.s_b1;
	b2 |= s_addr_in->sin_addr.S_un.S_un_b.s_b2;
	b3 |= s_addr_in->sin_addr.S_un.S_un_b.s_b3;
	b4 |= s_addr_in->sin_addr.S_un.S_un_b.s_b4;
	sprintf(to_string, "%u.%u.%u.%u", b1, b2, b3, b4);
	
	#else
	unsigned char *addr = (unsigned char *)&s_addr_in->sin_addr.s_addr;
	sprintf(to_string, "%u.%u.%u.%u", *(addr),*(addr+1),*(addr+2),*(addr+3));

	#endif
}


void copy_arr(char *to_copy, size_t firsts, char *copy){
    int i;
    for(i=0; i<firsts; i++)
        copy[i] = to_copy[i];
}

void encoding_xor_ip_same_file(char **to_encode, size_t len_to_enc, unsigned int seed){
	// CONTROLLO SE CI SONO BIT SPAIATI
	size_t resto = len_to_enc % 4;									// resto
	size_t cresto = resto == 0 ? 0 : (4 - resto);							// complemento del resto
	
	// IMPOSTO SEME DELLA FUNZIONE RAND A IP
	srand(seed);
		
	// CODIFICA
	int i;
	unsigned int *q_pla;
	for(i=0; i<len_to_enc; i+=4){										// Incremento ogni volta di 4 byte
		q_pla = (unsigned int *)((*to_encode)+i);							// 4-pla di byte
		if (i>len_to_enc-4){											// se e' l'ultima parola e la lunghezza non e' multiplo di 4
			unsigned int r = *q_pla;
			r <<=cresto*8;										// byte
			r >>=cresto*8;
		}
		*q_pla = *q_pla ^ ((unsigned int)rand());						// XOR bitwise
	}
}

/* 
 * deprecata in favore di encoding_xor_ip_same_file
 */
int encoding_xor_ip(char **to_encode, size_t len_to_enc, char **encoded, size_t *len_encded, unsigned int ip){
	// CONTROLLO SE LA LUNGHEZZA DEL FILE E' UGUALE A 0
	if(len_to_enc == 0)
		return FILE_EMPTY;

	// CONTROLLO SE CI SONO BIT SPAIATI
	size_t resto = len_to_enc % 4;									// resto
	size_t cresto = resto == 0 ? 0 : (4 - resto);							// complemento del resto
	*len_encded = len_to_enc + cresto;

	// INIZIALIZZO BUFFER DI RITORNO
	*encoded = NULL;

	*encoded = (char *) malloc(*len_encded);  
	if(*encoded == NULL){
		print_my_error("utility.encoding_xor_ip.encoded=...malloc");
		return GENERIC_INT_ERROR; 
	}

	copy_arr(*to_encode, len_to_enc, *encoded);							// ...cosicche la lunghezza sia divisibile per 4

	while(cresto > 0){													// aggiungo i byte spaiati
		(*encoded)[*len_encded-cresto] = 0;
		cresto--;
	}
    
	// IMPOSTO SEME DELLA FUNZIONE RAND A IP
	srand(ip);
    
	int i;
	for(i=0; i<*len_encded-3; i+=4){                                          // Incremento ogni volta di 4 byte
		unsigned int *q_pla = (unsigned int *)((*encoded)+i);                 // 4-pla di byte
		*q_pla = *q_pla ^ ((unsigned int)rand());                                           // XOR bitwise
	}

	return 0;
}

FILE_EXTENSION get_path_extension(PATH path){
	int i = -1;
	int j;
	for (j=0; j<strlen(path); j++) {
		if (path[j] == '.') {
			i=j;
		}
	}
	return &path[i];
}

char *get_username(char *usr_psswd){
	int i;
	for(i=0; i<strlen(usr_psswd); i++)
		if(usr_psswd[i]==':')
			break;
	i--;
	char *usr = malloc(i+2);
	copy_arr(usr_psswd, i+1, usr);
	usr[i+1] = '\0';
	return usr;
}

#ifndef _WIN32
long get_file_size(FILE *stream){
	int result = fseek(stream, 0, SEEK_END);
	long len_file = ftell(stream);															// ritorna la posizione in termini di offset in byte rispetto a 0
	rewind(stream);																	// riposizione il fd all'inizio del file
	return len_file;
}
#endif