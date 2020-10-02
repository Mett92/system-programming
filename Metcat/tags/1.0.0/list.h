/*
 *  list.c file
 *	Created by Mattia Paolacci
 */

#ifndef _LIST_H_
#define _LIST_H_

#ifndef _STDLIB_H
#include <stdlib.h>
#endif

#define ELEM_LIST_NOT_FOUND -1

typedef struct list{
    size_t size;    // quantita di elementi di tipo char* allocati
    size_t len;     // lunghezza della lista, ovvero numero di elementi inseriti
    char **array;    // puntatore alla lista
}list_t; //list di stringhe    

/*
 *  Crea una lista e ne restituisce il puntatore;
 *  @Return:
 *          list_t *: puntatore alla lista creata
 *          NULL    : in caso di errore in malloc
 */
list_t *get_new_list();

/*
 *  Restituisce la lista con l'elemento inserito alla fine
 *  @Param:
 *          list: lista a cui appendere l'elemento
 *          el  : elemento da appendere in coda
 *  @Return:
 *         0: se tutto ok
 *        -1: se occorso errore
 */
int append_to_list(list_t *l, char *el);

/*
 *  Rimuove l'elemento i-esimo dalla lista list.
 *  @Return:
 *          0: se tutto ok
 *         -1: se occorso errore
 */
int remove_elem_from_list(list_t *l, int i);

/*
 *  Ricerca all'interno della lista list una stringa uguale a str.
 *  @Return:
 *          i: ovvero la posizione i-esima dell'elemento nella lista
 *         -1: se l'elemento non c'e'
 */
int find_in_list(list_t *l, char *str);

/*  
 *  Ritorna un puntatore all'iesimo elemento
 *  @Return:
 *          char *  : se tutto ok
 *          NULL    : se errore occorso
 */
char *get_element_from_list(list_t *l, int i);

/* 
 *  Dealloca solo la memoria riservata alla lista e all'array in essa.
 *  NOTA:
 *      Nel caso in cui gli elementi puntati in list->array sono stati allocati dinamicamente, liberare quella memoria
 *      spetta al chiamante.
 */
void destroy_list(list_t *l);

#endif


