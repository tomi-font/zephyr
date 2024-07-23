/* SPDX-License-Identifier: Apache-2.0 */

#include <../library/psa_crypto_driver_wrappers.h>
#include <zephyr/secure_storage/its/storing.h>
#include <zephyr/init.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/util.h>
#include <errno.h>
#include <stdio.h>

SYS_INIT(settings_subsys_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

#define NAME_PREFIX_LEN (sizeof(CONFIG_SECURE_STORAGE_ITS_STORING_SETTINGS_PREFIX) - 1)

#ifdef CONFIG_SECURE_STORAGE_ITS_STORING_SETTINGS_ENCRYPT_UID

#include <zephyr/secure_storage/its/securing.h>

#define PSA_KEY_TYPE PSA_KEY_TYPE_AES
#define PSA_ALG PSA_ALG_ECB_NO_PADDING
#define NAME_CLEARTEXT_SIZE ROUND_UP(sizeof(secure_storage_its_uid_t), \
				     PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE))
#define NAME_CIPHERTEXT_SIZE PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE, PSA_ALG, \
							    NAME_CLEARTEXT_SIZE)
#define NAME_BUF_SIZE (NAME_PREFIX_LEN + 2 * NAME_CIPHERTEXT_SIZE + 1)

static psa_status_t make_name(secure_storage_its_uid_t uid, char name[static NAME_BUF_SIZE])
{
	psa_status_t ret;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key[CONFIG_SECURE_STORAGE_ITS_SECURING_KEY_SIZE];
	uint8_t cleartext[NAME_CLEARTEXT_SIZE];
	uint8_t ciphertext[NAME_CIPHERTEXT_SIZE];
	size_t ciphertext_len;

	ret = secure_storage_its_securing_get_key(uid, key);
	if (ret != PSA_SUCCESS) {
		return ret;
	}

	memcpy(cleartext, &uid, sizeof(uid));
	memset(cleartext + sizeof(uid), 0, sizeof(cleartext) - sizeof(uid));

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG);
	psa_set_key_bits(&key_attributes, sizeof(key) * 8);

	ret = psa_driver_wrapper_cipher_encrypt(&key_attributes, key, sizeof(key), PSA_ALG,
						NULL, 0, cleartext, sizeof(cleartext), ciphertext,
						sizeof(ciphertext), &ciphertext_len);
	if (ret != PSA_SUCCESS) {
		return ret;
	}
	strcpy(name, CONFIG_SECURE_STORAGE_ITS_STORING_SETTINGS_PREFIX);

	if (!bin2hex(ciphertext, ciphertext_len, name + NAME_PREFIX_LEN,
		     NAME_BUF_SIZE - NAME_PREFIX_LEN)) {
		return PSA_ERROR_STORAGE_FAILURE;
	}
	return PSA_SUCCESS;
}
#else
#define NAME_BUF_SIZE (NAME_PREFIX_LEN + 2 * (sizeof(secure_storage_its_uid_t) + 1))

static psa_status_t make_name(secure_storage_its_uid_t uid, char name[static NAME_BUF_SIZE])
{
	int ret;

	ret = snprintf(name, NAME_BUF_SIZE, "%s%x/%llx",
		       CONFIG_SECURE_STORAGE_ITS_STORING_SETTINGS_PREFIX, uid.caller_id, uid.uid);
	if (ret < 0 || ret >= NAME_BUF_SIZE) {
		return PSA_ERROR_STORAGE_FAILURE;
	}
	return PSA_SUCCESS;
}
#endif /* CONFIG_SECURE_STORAGE_ITS_STORING_SETTINGS_ENCRYPT_UID */

BUILD_ASSERT(NAME_BUF_SIZE <= SETTINGS_MAX_NAME_LEN + 1);

psa_status_t secure_storage_its_storing_set(secure_storage_its_uid_t uid, size_t data_length,
					    const void *data)
{
	psa_status_t ret;
	char name[NAME_BUF_SIZE];

	ret = make_name(uid, name);
	if (ret != PSA_SUCCESS) {
		return ret;
	}
	switch (settings_save_one(name, data, data_length)) {
	case 0:
		return PSA_SUCCESS;
	case -ENOMEM:
	case -ENOSPC:
		return PSA_ERROR_INSUFFICIENT_STORAGE;
	default:
		return PSA_ERROR_STORAGE_FAILURE;
	}
}

struct load_params {
	const size_t data_size;
	uint8_t *const data;
	ssize_t ret;
};

static int load_direct_setting(const char *, size_t len, settings_read_cb read_cb,
			       void *cb_arg, void *param)
{
	struct load_params *load_params = param;

	load_params->ret = read_cb(cb_arg, load_params->data, MIN(load_params->data_size, len));
	return 0;
}

psa_status_t secure_storage_its_storing_get(secure_storage_its_uid_t uid, size_t data_size,
					    void *data, size_t *data_length)
{
	psa_status_t ret;
	char name[NAME_BUF_SIZE];
	struct load_params load_params = {.data_size = data_size, .data = data, .ret = -ENOENT};

	ret = make_name(uid, name);
	if (ret != PSA_SUCCESS) {
		return ret;
	}
	settings_load_subtree_direct(name, load_direct_setting, &load_params);
	if (load_params.ret > 0) {
		*data_length = load_params.ret;
		return PSA_SUCCESS;
	} else {
		switch (load_params.ret) {
		case 0:
		case -ENOENT:
			return PSA_ERROR_DOES_NOT_EXIST;
		default:
			return PSA_ERROR_STORAGE_FAILURE;
		}
	}
}

psa_status_t secure_storage_its_storing_remove(secure_storage_its_uid_t uid)
{
	psa_status_t ret;
	char name[NAME_BUF_SIZE];

	ret = make_name(uid, name);
	if (ret != PSA_SUCCESS) {
		return ret;
	}

	switch (settings_delete(name)) {
	case 0:
		return PSA_SUCCESS;
	default:
		return PSA_ERROR_STORAGE_FAILURE;
	}
}
