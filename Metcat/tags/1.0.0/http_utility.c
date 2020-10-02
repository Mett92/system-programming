
#include <string.h>
#include <stdio.h>
#include "http_utility.h"
#include "utility.h"

// STRINGHE NOTE
#define SP " "
#define CRLF_STR "\r\n"
#define CR 13
#define LF 10

void init_response(http_response_t *resp){
    resp->body = NULL;
    resp->content_encoding = NULL;
    resp->content_length = NULL;
    resp->content_type = NULL;
    resp->status_line = NULL;
}

void init_request(http_request_t *req){
	req->authentication = NULL;
	req->body = NULL;
	req->content_length = 0;
	req->http_vers = NULL;
	req->method = NULL;
	req->uri = NULL;
	req->username = NULL;
}

int set_content_type(MIMETYPE mimetype, CONTENT_TYPE_PARAM charset, http_response_t *resp){
    size_t space_allocated = 0;
    size_t space_used = 0;
    resp->content_type = NULL;
    char name[] = "Content-Type: ";
    if(charset == NULL){
        charset="";
    }
    
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, name, strlen(name)) == -1)
        return -1;
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, mimetype, strlen(mimetype)) == -1)
        return -1;
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, ";", strlen(";")) == -1)
        return -1;
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, SP, strlen(SP)) == -1)
        return -1;
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, charset, strlen(charset)) == -1)
        return -1;
    if(concatenate_string(&resp->content_type, &space_used, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)
        return -1;
    resp->len_content_type = space_used;
    return 0;
}

int set_body(char *msg, size_t len_msg, http_response_t *resp){
    size_t space_allocated = 0;
    size_t space_used = 0;
    resp->body = NULL;

    if(concatenate_string(&resp->body, &space_used, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)                    // delimiter body
        return -1;       
    if(concatenate_string(&resp->body, &space_used, &space_allocated, msg, len_msg) == -1)                                  // corpo          
        return -1;
    
    resp->len_body = space_used;
    resp->content_length_uint = space_used-strlen(CRLF_STR);
    return 0;
}

int set_content_encoding(CONTENT_ENCODE encode, http_response_t *resp){
    size_t space_allocated = 0;
    size_t space_used = 0;
    resp->content_encoding = NULL;
    char name[] = "Content-Encoding: ";

    if(concatenate_string(&resp->content_encoding, &space_used, &space_allocated, name, strlen(name)) == -1)
        return -1;
    if(concatenate_string(&resp->content_encoding, &space_used, &space_allocated, encode, strlen(encode)) == -1)
        return -1;
    if(concatenate_string(&resp->content_encoding, &space_used, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)
        return -1;
    resp->len_content_encoding = space_used;
    return 0;
}

int set_content_length(http_response_t *resp){
    size_t space_allocated = 0;
    size_t space_used = 0;
    resp->content_length = NULL;
    char name[] = "Content-Length: ";
    char inttostr[15];
    sprintf(inttostr, "%lu", resp->content_length_uint);                   // size_t to string
    
    if(concatenate_string(&resp->content_length, &space_used, &space_allocated, name, strlen(name)) == -1)
        return -1;
    if(concatenate_string(&resp->content_length, &space_used, &space_allocated, inttostr, strlen(inttostr)) == -1)
        return -1;
    if(concatenate_string(&resp->content_length, &space_used, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)
        return -1;
    resp->len_content_length = space_used;
    return 0;
}

int set_status_line(STATUS_CODE code, http_response_t *resp){
    size_t space_allocated = 0;
    size_t space_used = 0;
    resp->status_line = NULL;
    resp->status_code = NULL;
    if( (resp->status_code = strcpy_da_a(code,0,2)) == NULL ){
        print_my_error("http_utility.set_status_line.strcpy_da_a");
        return -1;
    }

    if(concatenate_string(&resp->status_line, &space_used, &space_allocated, HTTP_VER, strlen(HTTP_VER)) == -1)
        return -1;
    if(concatenate_string(&resp->status_line, &space_used, &space_allocated, SP, strlen(SP)) == -1)
        return -1;
    if(concatenate_string(&resp->status_line, &space_used, &space_allocated, code, strlen(code)) == -1)
        return -1;
    if(concatenate_string(&resp->status_line, &space_used, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)
        return -1;
    resp->len_status_line = space_used;
    return 0;
}

int assemble_response(http_response_t *resp, size_t *len_http_msg, HTTP_MESSAGE *http_msg){
    size_t space_allocated = 0;
    size_t len_msg = 0;
    *http_msg = NULL; 
    
    if(resp->status_line != NULL)
        if(concatenate_string(http_msg,&len_msg, &space_allocated, resp->status_line, resp->len_status_line) == -1)
            return -1;
    if(resp->content_encoding != NULL)
         if(concatenate_string(http_msg,&len_msg, &space_allocated, resp->content_encoding, resp->len_content_encoding) == -1)
            return -1;
    if(resp->content_type != NULL)
         if(concatenate_string(http_msg,&len_msg, &space_allocated, resp->content_type, resp->len_content_type) == -1)
            return -1;
    if(resp->content_length != NULL)
         if(concatenate_string(http_msg,&len_msg, &space_allocated, resp->content_length, resp->len_content_length) == -1)
            return -1;
    if(resp->body != NULL)
         if(concatenate_string(http_msg,&len_msg, &space_allocated, resp->body, resp->len_body) == -1)
            return -1;

    // SE BODY NON DEFINITO INSERISCO ACCAPO
    if(resp->body == NULL){                                                                             
        if(concatenate_string(http_msg,&len_msg, &space_allocated, CRLF_STR, strlen(CRLF_STR)) == -1)
            return -1;
    }
    *len_http_msg = len_msg;

    return 0;
}

int find_end_header(HTTP_MESSAGE msg, size_t len_msg){
    int res = find_bodys_start(msg,len_msg);
    return res == 0 ? 0 : res - 2 * strlen(CRLF_STR);
}

int find_bodys_start(HTTP_MESSAGE msg, size_t len_msg){
    int ret = 0;

    int i;
    for(i=0; i<len_msg; i++)
        if( (msg[i] == CR) && (msg[i+1] == LF) && (msg[i+2] == CR) && (msg[i+3] == LF) ){
            ret = i+4;
            break;
        }

    return ret;
}

void free_http_request(http_request_t *req){
	free(req->authentication);
	free(req->http_vers);
	free(req->method);
	free(req->uri);
	free(req->body);
	free(req->username);
}

void free_http_response(http_response_t *resp){
    free(resp->body);
    free(resp->content_encoding);
    free(resp->content_length);
    free(resp->content_type);
    free(resp->status_line);
    free(resp->status_code);
}


