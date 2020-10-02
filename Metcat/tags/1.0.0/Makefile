LIB=
WIN_EXE=
APP_NAME=Metcat
WIN_SRC=
ifeq ($(OS),Windows_NT)
	RM =del
	LIB +=-lws2_32 -lShlwapi -lkernel32 -lgdi32
	WIN_EXE+=process_pool.exe
	WIN_SRC+=manage_connection.o manage_authentication.o utility.o list.o b_64.o functionality.o http_utility.o mime_type_utility.o manage_configuration.o log4c.o

else
	RM =rm
endif
	FILES =manage_connection.o manage_authentication.o utility.o server.o list.o b_64.o functionality.o http_utility.o mime_type_utility.o manage_configuration.o log4c.o

ServerApp: $(FILES) $(WIN_EXE) 
	gcc $(FILES) $(LIB) -o $(APP_NAME)

server.o: server.c server.h
	gcc -c server.c

process_pool.exe: process_pool.c $(WIN_SRC)
	gcc process_pool.c $(WIN_SRC) $(LIB) -o process_pool.exe

log4c.o: log4c.h log4c.c
	gcc -c log4c.c

manage_connection.o: manage_connection.c manage_connection.h
	gcc -c manage_connection.c

manage_authentication.o: manage_authentication.h manage_authentication.c
	gcc -c manage_authentication.c 

utility.o: utility.h utility.c
	gcc -c utility.c

list.o: list.c list.h 
	gcc -c list.c

b_64.o: b_64.h b_64.c
	gcc -c b_64.c

functionality.o: functionality.c functionality.h
	gcc -c functionality.c

http_utility.o: http_utility.c http_utility.h
	gcc -c http_utility.c

mime_type_utility.o: mime_type_utility.c mime_type_utility.h
	gcc -c mime_type_utility.c

manage_configuration.o: manage_configuration.h manage_configuration.c
	gcc -c manage_configuration.c

clean:
	$(RM) *.o | $(RM) *.gch