# Compiler options.
CC = gcc
CFLAGS = -lcrypto -lssl -I/opt/homebrew/Cellar/openssl@3/3.0.0_1/include
LDFLAGS = -L/opt/homebrew/Cellar/openssl@3/3.0.0_1/lib -lpthread

all			: webproxy

webserver	: webproxy.c webproxy.h
			$(CC) $(CFLAGS) $(LDFLAGS) -o webproxy webproxy.c

clean:
	rm webproxy
