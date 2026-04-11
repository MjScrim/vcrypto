CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../../include
TARGET = libvcrypto.a

all: $(TARGET)

$(TARGET): vcrypto.o
	ar rcs $(TARGET) vcrypto.o

vcrypto.o: vcrypto.c ../../include/vcrypto.h ../../include/vcrypto_ioctl.h
	$(CC) $(CFLAGS) -c vcrypto.c

clean:
	rm -f *.o $(TARGET)
