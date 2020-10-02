#ifndef	_SERVER_H_
#define	_SERVER_H_

// LUNGHEZZA MASSIMA PATH 
#define MAX_PATH_LEN 256

// FLAG PER I PARAMETRI DA PASSARE IN INPUT AL MAIN									
#define FLAG_CONGIF "-C"										// Flag per il percorso del file di configurazione

typedef struct params_main{
	short n_thread;
	short n_proc;
	short port_num;
	char conf_path[MAX_PATH_LEN];
	char *cmd_path;										// e' il path del cmd dell'applicazione
}params_main_t;

/*
 *	Legge i parametri passati al main e controlla che siano ben formati.
 *	@Return:
 *			0: se gli argomenti sono coerenti con i vincoli;
 *		   -1: altrimenti
 */
int check_arguments(int argc, char **argv);

/*
 *	Setta la gestione di alcuni segnali/eventi sotto unix/windows
 */
int set_console_handler();

#ifndef _WIN32
int deamonize();
#endif

/*
 *	pone il processo in attesa di un evento.
 */
void attesa_evento_tastiera();

#ifdef _WIN32

void manage_ctrl_c();

/*
 *	Effettua una fork del processo init, se errore restituisce null.
 */
int fork_process(PROCESS_INFORMATION *proc_info_out, MODE flag_encipher);

void kill_thread_pool(HANDLE *threads, int n_threads);

/*
 *	Killa i primi j processi, presenti in procs_arr
 */
int kill_processes_pool(int j, PROCESS_INFORMATION *procs_arr, int len_arr);

/*
 *	Genera il pool di processi del server inizializzando procs_arr
 */
int crea_pool_di_processi(PROCESS_INFORMATION **procs_arr, int procs_to_create, MODE flag_encipher);

/*
 *	Genera il pool di thread del server.
 */
void crea_pool_di_thread(HANDLE **threads_array, int threads_to_create, MODE flag_encipher);

DWORD WINAPI thread_task(LPVOID flag_encipher);

/*
 *	Gestisce l'evento console CTRL+C sotto WINDOWS
 */
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);
#endif

#ifndef _WIN32
void thread_task(MODE flag_encipher);

/*
 *	Killa i primi j processi, presenti in procs_arr
 */
int kill_processes_pool(pid_t *procs_arr, int j, int len_arr);

/*
 *	Genera il pool di processi del server.
 */
int crea_pool_di_processi();

/*
 *	killa tutti i thread nell'array
 */
int kill_thread_pool(pthread_t *threads_arr, int len_arr, int sig);

/*
 *	Genera il pool di thread del server.
 */
void crea_pool_di_thread(pthread_t **threads_arr, int threads_to_create, MODE flag_encipher);

void manage_sighup();

void signal_handler(int sig);

void manage_sigterm();

void manage_sigterm_thread();

#endif



/* 
 *					MAN PAGE
 * 	NAME: servapp
 * 	
 * 	SYNOPSIS:
 * 		servapp [ [ -T n_tread ] ^ [ -P n_proc ] ] [ -A porta ]
 * 
 * 	Il file di configurazione ha un path di default da cui il programma andra 
 * 		a leggere i paramtri se questi non sono dati in input
 */

#endif