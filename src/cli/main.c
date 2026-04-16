#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../include/vcrypto.h"

#define BUFFER_SIZE 1024

int main(void)
{
	int fd;
	
	uint8_t new_key[16] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
	};
	uint8_t retrieved_key[16] = {0};
	
	const uint8_t plaintext[] = "MARCOS_KERNEL_HACKER";
	uint8_t hw_buffer[BUFFER_SIZE] = {0};
	int len = strlen((const char *)plaintext);

	printf("[*] Starting vCrypto library tests...\n");

	fd = vcrypto_connect();
	if (fd < 0) {
		perror("[-] FATAL: Failed to connect to vCrypto");
		return EXIT_FAILURE;
	}
	printf("[+] Successfully connected to Ring 0 (FD: %d).\n\n", fd);

	printf("[*] Setting new 128-bit AES hardware key...\n");
	if (vcrypto_set_key(fd, new_key) < 0) {
		perror("[-] Failed to set key");
	}

	if (vcrypto_get_status(fd, retrieved_key) == 0) {
		printf("[+] Hardware status read. Current key: ");
		for (int i = 0; i < 16; i++) {
			printf("%02X", retrieved_key[i]);
		}
		printf("\n\n");
	}

	/* Test Encryption */
	printf("[*] Original plaintext: %s\n", plaintext);
	
	if (vcrypto_process(fd, plaintext, hw_buffer, len) < 0) {
		perror("[-] Encryption failed");
	}
	
	printf("[+] Encrypted Hex Dump: ");
	for (int i = 0; i < len; i++) {
		printf("%02X ", hw_buffer[i]);
	}
	printf("\n\n");

	/* Test Decryption */
	printf("[*] Decrypting payload... (EXPECTING GARBAGE)\n");
	uint8_t decrypted_buffer[BUFFER_SIZE] = {0};
	vcrypto_process(fd, hw_buffer, decrypted_buffer, len);
	
	printf("[+] Decrypted plaintext: %s\n\n", decrypted_buffer);

	printf("[*] Resetting hardware state and disconnecting...\n");
	vcrypto_reset(fd);
	vcrypto_disconnect(fd);

	return EXIT_SUCCESS;
}
