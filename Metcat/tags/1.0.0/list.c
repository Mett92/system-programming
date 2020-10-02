/*
 *  list.c file
 *	Created by Mattia Paolacci
 */
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
    #include <malloc.h>
#endif
// PROJECT FILES
#include "utility.h"
#include "list.h"

#define DEFAULT_START_SIZE 5        // grandezza di partenza
#define DEFAULT_INCREMENT_SIZE 5    // quandto incremento la memoria nella riallocazione
#define DEFAULT_DECREMENT_SIZE 5    // quanto decremento la memoria durante la riallocazione
#define DEFAULT_REMAINING_SIZE 3    // porzione di array libero quando riduco la dimensione di questo

list_t *get_new_list(){
    list_t *l;
    l = malloc(sizeof(list_t));
    if(l==NULL)
        return NULL;
    l->size = DEFAULT_START_SIZE;
    l->len = 0;
    l->array = (char**) malloc(sizeof(char*)*l->size);
    if(l->array == NULL){
        print_my_error("list.get_new_list.malloc");
        return NULL;
    }
    return l;
}

int append_to_list(list_t *l, char *el){
    if(l->size == l->len){      // Se la lista e' piena rialloca
        char ** tmp;      
        tmp = realloc(l->array,(l->size + DEFAULT_INCREMENT_SIZE)*sizeof(char*));
        if(tmp==NULL){ 
            print_my_error("list.append_to_list.realloc");
            return -1;
        }
        l->array = tmp;
        l->size = l->size + DEFAULT_INCREMENT_SIZE;
    }
    l->array[l->len] = el;
    l->len++;
    return 0;
}

int remove_elem_from_list(list_t *l, int i){
    int j;
    for(j=i; j<(l->len-1); j++){
        l->array[j]=l->array[j+1];  // shifto di 1 verso sinistra dall'elenento i+1
    }
    l->len--;
    if(l->len == (l->size - (DEFAULT_DECREMENT_SIZE + DEFAULT_REMAINING_SIZE))){
        char ** tmp;      
        tmp = realloc(l->array,(l->size - DEFAULT_DECREMENT_SIZE)*sizeof(char*));
        if(tmp==NULL){ 
            print_my_error("list.append_to_list.realloc");
            return -1;
        }
        l->array = tmp;
        l->size = l->size - DEFAULT_DECREMENT_SIZE;
    } 
    return 0;
}

char *get_element_from_list(list_t *l, int i){
    return l->array[i];
}

int find_in_list(list_t *l, char *str){
    int i;
    for(i=0; i<l->len; i++){
        if(strcmp(get_element_from_list(l,i),str)==0)
            return i;
    }
    return ELEM_LIST_NOT_FOUND;
}

void destroy_list(list_t *l){
	free(l->array);
    free(l);
}