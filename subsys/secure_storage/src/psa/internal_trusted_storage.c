/* SPDX-License-Identifier: Apache-2.0 */

#include <psa/internal_trusted_storage.h>
#include <zephyr/secure_storage/its.h>
#include "helpers.h"

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
			 psa_storage_create_flags_t create_flags)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_length, p_data)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_set(CONFIG_SECURE_STORAGE_PSA_ITS_PREFIX,
				      uid, data_length, p_data, create_flags);
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size,
			 void *p_data, size_t *p_data_length)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_size, p_data)
	 || !validate_ptr(p_data_length)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_get(CONFIG_SECURE_STORAGE_PSA_ITS_PREFIX,
				      uid, data_offset, data_size, p_data, p_data_length);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
	if (!validate_uid(uid)
	 || !validate_ptr(p_info)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_get_info(CONFIG_SECURE_STORAGE_PSA_ITS_PREFIX,
					   uid, p_info);
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
	if (!validate_uid(uid)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_remove(CONFIG_SECURE_STORAGE_PSA_ITS_PREFIX,
					 uid);
}
