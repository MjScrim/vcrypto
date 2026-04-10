#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

/* Include the shared IOCTL contract */
#include "../../include/vcrypto_ioctl.h"

#define DEVICE_PATH "/dev/vcrypto"
#define BUFFER_SIZE 1024

int main(void)
{
	int fd;
	int new_key = 0xAA; /* Arbitrary key for XOR */
	int retrieved_key = 0;
	const char *plaintext = "MARCOS_KERNEL_HACKER";
	char hw_buffer[BUFFER_SIZE] = {0};
	int bytes_processed;

	printf("[*] Attempting to open cryptographic coprocessor at %s...\n", DEVICE_PATH);
	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		perror("[-] FATAL: Failed to open device. Is the vcrypto module loaded?");
		return EXIT_FAILURE;
	}
	printf("[+] Device opened successfully.\n\n");

	/* Test 1: IOCTL SET_KEY */
	printf("[*] Sending VCRYPTO_SET_KEY command (Key: 0x%X)...\n", new_key);
	if (ioctl(fd, VCRYPTO_SET_KEY, &new_key) < 0) {
		perror("[-] IOCTL SET_KEY failed");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Test 2: IOCTL GET_STATUS */
	printf("[*] Sending VCRYPTO_GET_STATUS command to verify state...\n");
	if (ioctl(fd, VCRYPTO_GET_STATUS, &retrieved_key) == 0) {
		printf("[+] Hardware confirmed current key: 0x%X\n\n", retrieved_key);
	} else {
		perror("[-] IOCTL GET_STATUS failed");
	}

	/* Test 3: Encryption (Write -> Read) */
	printf("[*] Original plaintext: %s\n", plaintext);
	printf("[*] Writing data to Ring 0 for encryption...\n");
	
	bytes_processed = write(fd, plaintext, strlen(plaintext));
	if (bytes_processed < 0) {
		perror("[-] Write operation failed");
		close(fd);
		return EXIT_FAILURE;
	}

	printf("[*] Reading encrypted data from Ring 0...\n");
	read(fd, hw_buffer, bytes_processed);

	printf("[+] Encrypted Hex Dump: ");
	for (int i = 0; i < bytes_processed; i++) {
		printf("%02X ", (unsigned char)hw_buffer[i]);
	}
	printf("\n\n");

	/* Test 4: Decryption (Write -> Read with the same XOR key) */
	printf("[*] Writing encrypted payload back to hardware for decryption...\n");
	write(fd, hw_buffer, bytes_processed);
	
	memset(hw_buffer, 0, BUFFER_SIZE); /* Clear local buffer before reading */
	
	read(fd, hw_buffer, bytes_processed);
	printf("[+] Decrypted plaintext: %s\n\n", hw_buffer);

	/* Test 5: IOCTL RESET */
	printf("[*] Sending VCRYPTO_RESET command to wipe hardware memory...\n");
	if (ioctl(fd, VCRYPTO_RESET) < 0) {
		perror("[-] IOCTL RESET failed");
	}

	printf("[*] Closing device...\n");
	close(fd);

	return EXIT_SUCCESS;
}
