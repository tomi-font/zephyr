/* SPDX-License-Identifier: Apache-2.0 */

#include <../library/psa_crypto_driver_wrappers.h>
#include <zephyr/secure_storage/its/securing.h>
#include <zephyr/drivers/hwinfo.h>
#include <psa/crypto.h>
#include <stdbool.h>
#include <string.h>

#ifdef CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_PROVIDER_DEFAULT

psa_status_t secure_storage_its_securing_get_key(secure_storage_its_uid_t uid, uint8_t key[static
						 CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE])
{
	struct {
		secure_storage_its_uid_t uid;
		uint8_t device_id[8];
	} __packed hash_input = {
		.uid = uid,
	};
	size_t hash_input_len = sizeof(hash_input.uid);
	size_t hash_len;

#ifdef CONFIG_HWINFO
	ssize_t hwinfo_ret;

	hwinfo_ret = hwinfo_get_device_eui64(hash_input.device_id);
	if (hwinfo_ret == 0) {
		hash_input_len += 8;
	} else {
		hwinfo_ret = hwinfo_get_device_id(hash_input.device_id,
						  sizeof(hash_input.device_id));
		if (hwinfo_ret > 0) {
			hash_input_len += hwinfo_ret;
		}
	}
#endif /* CONFIG_HWINFO */

	enum { HASH_OUTPUT_LEN = PSA_HASH_LENGTH(PSA_ALG_SHA_256) };
	BUILD_ASSERT(CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE <= HASH_OUTPUT_LEN);

	if (CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE == HASH_OUTPUT_LEN) {
		return psa_hash_compute(PSA_ALG_SHA_256, (uint8_t*)&hash_input, hash_input_len, key,
					CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE, &hash_len);
	} else {
		uint8_t hash_output[HASH_OUTPUT_LEN];
		psa_status_t ret = psa_hash_compute(PSA_ALG_SHA_256, (uint8_t*)&hash_input,
						    hash_input_len, hash_output,
						    sizeof(hash_output), &hash_len);

		if (ret == PSA_SUCCESS) {
			memcpy(key, hash_output, CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE);
		}
		return ret;
	}
}
#endif /* CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_PROVIDER_DEFAULT */

#ifdef CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_PROVIDER_DEFAULT

psa_status_t secure_storage_its_securing_get_nonce(uint8_t nonce[static
						   CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE])
{
	psa_status_t ret;
	static uint8_t s_nonce[CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE];
	static bool s_nonce_initialized;

	if (!s_nonce_initialized) {
		ret = psa_generate_random(s_nonce, sizeof(s_nonce));
		if (ret != PSA_SUCCESS) {
			return ret;
		}
		s_nonce_initialized = true;
	} else {
		for (unsigned int i = 0; i != sizeof(s_nonce); ++i) {
			++s_nonce[i];
			if (s_nonce[i] != 0) {
				break;
			}
		}
	}

	memcpy(nonce, &s_nonce, sizeof(s_nonce));
	return PSA_SUCCESS;
}
#endif /* CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_PROVIDER_DEFAULT */

#ifdef CONFIG_SECURE_STORAGE_ITS_SECURING_AEAD_SCHEME_PROVIDER_DEFAULT

void secure_storage_its_securing_get_aead_scheme(psa_key_type_t *key_type, psa_algorithm_t *alg)
{
	*key_type = PSA_KEY_TYPE_AES;
	*alg = PSA_ALG_GCM;
}
#endif /* CONFIG_SECURE_STORAGE_ITS_SECURING_AEAD_SCHEME_PROVIDER_DEFAULT */

#ifndef CONFIG_SECURE_STORAGE_ITS_SECURING_AEAD_CRYPT_IMPLEMENTATION_CUSTOM

psa_status_t secure_storage_its_securing_aead_crypt(psa_key_usage_t operation,
						    secure_storage_its_uid_t uid,
						    const uint8_t nonce[static
						    CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE],
						    size_t add_data_len, const void *add_data,
						    size_t input_len, const void *input,
						    size_t output_size, void *output,
						    size_t *output_len)
{
	psa_status_t ret;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key[CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE];
	psa_key_type_t key_type;
	psa_algorithm_t alg;
	psa_status_t (*aead_crypt)(const psa_key_attributes_t *attributes, const uint8_t *key,
				   size_t key_size, psa_algorithm_t alg, const uint8_t *nonce,
				   size_t nonce_length, const uint8_t *add_data,
				   size_t add_data_len, const uint8_t *input, size_t input_len, uint8_t *output, size_t output_size, size_t *output_len);

	ret = secure_storage_its_securing_get_key(uid, key);
	if (ret != PSA_SUCCESS) {
		return ret;
	}
	secure_storage_its_securing_get_aead_scheme(&key_type, &alg);

	psa_set_key_usage_flags(&key_attributes, operation);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&key_attributes, key_type);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_bits(&key_attributes, sizeof(key) * 8);

	aead_crypt = (operation == PSA_KEY_USAGE_ENCRYPT) ?
		      psa_driver_wrapper_aead_encrypt : psa_driver_wrapper_aead_decrypt;

	ret = aead_crypt(&key_attributes, key, sizeof(key), alg, nonce,
			 CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE, add_data, add_data_len,
			 input, input_len, output, output_size, output_len);
	return ret;
}
#endif /* !CONFIG_SECURE_STORAGE_ITS_SECURING_AEAD_CRYPT_IMPLEMENTATION_CUSTOM */
