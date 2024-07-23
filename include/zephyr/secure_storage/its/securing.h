#ifndef SECURE_STORAGE_ITS_SECURING_H
#define SECURE_STORAGE_ITS_SECURING_H

#include <zephyr/secure_storage/its/common.h>
#include <psa/crypto_types.h>

psa_status_t secure_storage_its_securing_get_key(secure_storage_its_uid_t uid, uint8_t key[static
						 CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE]);

psa_status_t secure_storage_its_securing_get_nonce(uint8_t nonce[static
						   CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE]);

void secure_storage_its_securing_get_aead_scheme(psa_key_type_t *key_type, psa_algorithm_t *alg);

psa_status_t secure_storage_its_securing_aead_crypt(psa_key_usage_t operation,
						    secure_storage_its_uid_t uid,
						    const uint8_t nonce[static
						    CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE],
						    size_t add_data_len, const void *add_data,
						    size_t input_len, const void *input,
						    size_t output_size, void *output,
						    size_t *output_len);

#endif
