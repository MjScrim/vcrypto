#ifndef VCRYPTO_H
#define VCRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int vcrypto_connect(void);

int vcrypto_set_key(int fd, int key);

int vcrypto_get_status(int fd, int *current_key);

ssize_t vcrypto_process(int fd, const uint8_t *input, uint8_t *output, size_t len);

int vcrypto_reset(int fd);

void vcrypto_disconnect(int fd);

#endif /* VCRYPTO_H */
