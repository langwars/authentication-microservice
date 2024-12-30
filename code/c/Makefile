CC=gcc
CFLAGS=-I/opt/homebrew/opt/openssl@3/include -O3 -march=native -pthread -flto
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -pthread

all: auth

auth: auth.c
	$(CC) $(CFLAGS) -o auth auth.c $(LDFLAGS)

clean:
	rm -f auth
