/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/secure_storage/its/impl.h>
#include <zephyr/secure_storage/its/securing.h>
#include <zephyr/secure_storage/its/storing.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>
#include <psa/crypto.h>
#include <string.h>

#define CIPHERTEXT_SIZE PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE)

struct stored_entry {
	psa_storage_create_flags_t create_flags;
	uint8_t nonce[CONFIG_SECURE_STORAGE_ITS_SECURING_NONCE_SIZE];
	uint8_t ciphertext[CIPHERTEXT_SIZE];
} __packed;

/** @return The length of a `struct stored_entry` whose `ciphertext` is `len` bytes long. */
#define STORED_ENTRY_LEN(len) (sizeof(struct stored_entry) - CIPHERTEXT_SIZE + len)

struct additional_data {
	secure_storage_its_uid_t uid;
	psa_storage_create_flags_t create_flags;
} __packed;

static psa_status_t get_entry(secure_storage_its_uid_t uid,
			      psa_storage_create_flags_t *create_flags, size_t data_size,
			      uint8_t *data, size_t *data_len)
{
	psa_status_t ret;
	struct stored_entry stored_entry;
	size_t stored_entry_len;

	ret = secure_storage_its_storing_get(uid, sizeof(stored_entry), &stored_entry,
					     &stored_entry_len);
	if (ret != PSA_SUCCESS) {
		return ret;
	} else if (stored_entry_len < STORED_ENTRY_LEN(0)) {
		return PSA_ERROR_STORAGE_FAILURE;
	}

	const struct additional_data add_data = {.uid = uid,
						 .create_flags = stored_entry.create_flags};
	const size_t ciphertext_len = stored_entry_len - STORED_ENTRY_LEN(0);

	ret = secure_storage_its_securing_aead_crypt(PSA_KEY_USAGE_DECRYPT, uid, stored_entry.nonce,
						     sizeof(add_data), &add_data, ciphertext_len,
						     &stored_entry.ciphertext, data_size, data,
						     data_len);
	if (ret == PSA_SUCCESS && create_flags != NULL) {
		*create_flags = stored_entry.create_flags;
	}
	return ret;
}

static psa_status_t verify_write_once_flag_not_set(secure_storage_its_uid_t uid, uint8_t data
						   [static CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE],
						   size_t *data_len)
{
	psa_status_t ret;
	psa_storage_create_flags_t create_flags;

	ret = get_entry(uid, &create_flags, CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE, data,
			data_len);
	if (ret == PSA_SUCCESS) {
		if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
			return PSA_ERROR_NOT_PERMITTED;
		}
	} else if (ret != PSA_ERROR_DOES_NOT_EXIST) {
		return ret;
	}
	return PSA_SUCCESS;
}

psa_status_t secure_storage_its_impl_set(secure_storage_its_uid_t uid, size_t data_length,
					 const void *p_data,
					 psa_storage_create_flags_t create_flags)
{
	psa_status_t ret;

	if (data_length > CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE) {
		return PSA_ERROR_INSUFFICIENT_STORAGE;
	}

	{
		uint8_t data[CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE];
		size_t data_len;

		ret = verify_write_once_flag_not_set(uid, data, &data_len);
		if (ret != PSA_SUCCESS) {
			return ret;
		}
		if (data_len == data_length && memcmp(data, p_data, data_length) == 0) {
			return PSA_SUCCESS;
		}
	}

	const struct additional_data add_data = {.uid = uid, .create_flags = create_flags};
	struct stored_entry stored_entry;
	size_t ciphertext_len;

	ret = secure_storage_its_securing_get_nonce(stored_entry.nonce);
	if (ret != PSA_SUCCESS) {
		return ret;
	}

	ret = secure_storage_its_securing_aead_crypt(PSA_KEY_USAGE_ENCRYPT, uid,
						     stored_entry.nonce, sizeof(add_data),
						     &add_data, data_length, p_data,
						     sizeof(stored_entry.ciphertext),
						     &stored_entry.ciphertext,
						     &ciphertext_len);
	if (ret != PSA_SUCCESS) {
		return ret;
	}
	stored_entry.create_flags = create_flags;

	ret = secure_storage_its_storing_set(uid, STORED_ENTRY_LEN(ciphertext_len),
					     &stored_entry);

	return ret;
}

psa_status_t secure_storage_its_impl_get(secure_storage_its_uid_t uid, size_t data_offset,
					 size_t data_size, void *p_data, size_t *p_data_length)
{
	if (data_offset == 0) {
		return get_entry(uid, NULL, data_size, p_data, p_data_length);
	}

	psa_status_t ret;
	uint8_t data[CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE];
	size_t data_len;

	ret = get_entry(uid, NULL, sizeof(data), data, &data_len);
	if (ret == PSA_SUCCESS) {
		if (data_offset > data_len) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
		*p_data_length = MIN(data_size, data_len - data_offset);
		memcpy(p_data, data + data_offset, *p_data_length);
	}
	return ret;
}

psa_status_t secure_storage_its_impl_get_info(secure_storage_its_uid_t uid,
					      struct psa_storage_info_t *p_info)
{
	psa_status_t ret;
	uint8_t data[CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE];

	ret = get_entry(uid, &p_info->flags, sizeof(data), data, &p_info->size);
	if (ret != PSA_SUCCESS) {
		return ret;
	}

	p_info->capacity = p_info->size;
	return PSA_SUCCESS;
}

psa_status_t secure_storage_its_impl_remove(secure_storage_its_uid_t uid)
{
	psa_status_t ret;
	uint8_t data[CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE];
	size_t data_len;

	ret = verify_write_once_flag_not_set(uid, data, &data_len);
	if (ret == PSA_SUCCESS) {
		ret = secure_storage_its_storing_remove(uid);
	}
	return ret;
}
