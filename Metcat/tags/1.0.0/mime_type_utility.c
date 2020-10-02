#include "mime_type_utility.h"
#include "utility.h"
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
	#include <shlwapi.h>
#endif

//  TEXT/
static const char text_plain[] = "text/plain";
static const char text_html[] = "html/text";

//  APPLICATION/
static const char application_rtf[] = "application/rtf";
static const char application_zip[] = "application/zip";
static const char application_xrar_compr[] = "application/x-rar-compressed"; 
static const char application_pdf[] = "application/pdf";

// DIMENSIONE DELLA MAPPA
#define LEN_MIMETYPE_MAP 6

static const char *mime_map[][2] = {
                        {".txt", text_plain},
                        {".rtf", application_rtf},
                        {".rar", application_xrar_compr},
                        {".zip", application_zip},
                        {".html", text_html},
                        {".pdf", application_pdf}
};


int get_file_mimetype(char *file_name, MIMETYPE mimetype){
	FILE_EXTENSION file_ext = get_path_extension(file_name);
    int i;
    for(i=0; i<LEN_MIMETYPE_MAP; i++){
        if(strcmp(file_ext,(mime_map[i])[0]) == 0){
            copy_str_in_arr((char *)mime_map[i][1], mimetype);
            return 1;
        }
    }
    return 0;
}

