#ifndef VCRYPTO_AES_H
#define VCRYPTO_AES_H

#include <linux/types.h>

#define AES_BLOCK_SIZE 16

size_t aes_apply_padding(uint8_t *buffer, size_t current_len, size_t max_len);
void aes_expand_key(const uint8_t *key, uint8_t *expanded_key);
void aes_encrypt_block(uint8_t *state, const uint8_t *expanded_key);

#endif /* VCRYPYO_AES_H */
