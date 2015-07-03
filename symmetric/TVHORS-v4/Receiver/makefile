CC = gcc
CFLAGS  = -g -lcrypto -lpthread

# the build target executable:
TARGET = Server

all:
	gcc -o server Server.c -lcrypto -lpthread

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)

cross:
	arm-linux-gnueabi-gcc -I -lssleay32 Server.c -o server -leay32 -lpthread
