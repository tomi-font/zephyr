/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/secure_storage/its/implementation.h>
#include <zephyr/secure_storage/its/internal.h>
#include "helpers.h"

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
			 psa_storage_create_flags_t create_flags)
{
	return secure_storage_its_set(uid, data_length, p_data, create_flags,
				      SECURE_STORAGE_ITS_CALLER_EXTERNAL);
}

psa_status_t secure_storage_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
				    psa_storage_create_flags_t create_flags,
				    secure_storage_its_caller_id_t caller_id)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_length, p_data)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_impl_set(uid, data_length, p_data, create_flags, caller_id);
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size,
			 void *p_data, size_t *p_data_length)
{
	return secure_storage_its_get(uid, data_offset, data_size, p_data, p_data_length,
				      SECURE_STORAGE_ITS_CALLER_EXTERNAL);
}

psa_status_t secure_storage_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size,
				    void *p_data, size_t *p_data_length,
				    secure_storage_its_caller_id_t caller_id)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_size, p_data)
	 || !validate_ptr(p_data_length)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_impl_get(uid, data_offset, data_size, p_data, p_data_length,
					   caller_id);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
	return secure_storage_its_get_info(uid, p_info, SECURE_STORAGE_ITS_CALLER_EXTERNAL);
}

psa_status_t secure_storage_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info,
					 secure_storage_its_caller_id_t caller_id)
{
	if (!validate_uid(uid)
	 || !validate_ptr(p_info)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_impl_get_info(uid, p_info, caller_id);
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
	return secure_storage_its_remove(uid, SECURE_STORAGE_ITS_CALLER_EXTERNAL);
}

psa_status_t secure_storage_its_remove(psa_storage_uid_t uid,
				       secure_storage_its_caller_id_t caller_id)
{
	if (!validate_uid(uid)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_its_impl_remove(uid, caller_id);
}
