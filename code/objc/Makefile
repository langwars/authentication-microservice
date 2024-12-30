CC=clang
CFLAGS=-framework Foundation -fobjc-arc
TARGET=auth_server

$(TARGET): AuthServer.m
	$(CC) $(CFLAGS) -o $(TARGET) AuthServer.m

clean:
	rm -f $(TARGET)
