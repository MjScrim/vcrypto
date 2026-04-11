#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Import our clean Ring 3 API */
#include "../../include/vcrypto.h"

#define BUFFER_SIZE 1024

int main(void)
{
	int fd;
	int new_key = 0xAA;
	int retrieved_key = 0;
	
	/* Using uint8_t for strict binary data compatibility */
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

	printf("[*] Setting hardware key to 0x%X...\n", new_key);
	if (vcrypto_set_key(fd, new_key) < 0) {
		perror("[-] Failed to set key");
	}

	if (vcrypto_get_status(fd, &retrieved_key) == 0) {
		printf("[+] Hardware status read. Current key: 0x%X\n\n", retrieved_key);
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
	printf("[*] Decrypting payload via involutory XOR...\n");
	uint8_t decrypted_buffer[BUFFER_SIZE] = {0};
	vcrypto_process(fd, hw_buffer, decrypted_buffer, len);
	
	printf("[+] Decrypted plaintext: %s\n\n", decrypted_buffer);

	printf("[*] Resetting hardware state and disconnecting...\n");
	vcrypto_reset(fd);
	vcrypto_disconnect(fd);

	return EXIT_SUCCESS;
}
