CC=gcc
CFLAGS=-I/opt/homebrew/opt/openssl@3/include -O3 -march=native -pthread -flto
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -pthread

all: auth_service auth_service_v2

auth_service: auth_service.c
	$(CC) $(CFLAGS) -o auth_service auth_service.c $(LDFLAGS)

auth_service_v2: auth_service_v2.c
	$(CC) $(CFLAGS) -o auth_service_v2 auth_service_v2.c $(LDFLAGS)

clean:
	rm -f auth_service auth_service_v2
