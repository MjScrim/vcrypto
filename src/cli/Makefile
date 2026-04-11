CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = vcrypto-cli

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c ../lib/libvcrypto.a

clean:
	rm -f $(TARGET)
