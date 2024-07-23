/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/secure_storage/its/impl.h>
#include <zephyr/secure_storage/its/internal.h>
#include "helpers.h"

#define ITS_UID (secure_storage_its_uid_t){.uid = uid, .caller_id = caller_id}

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
			 psa_storage_create_flags_t create_flags)
{
	return secure_storage_its_set(uid, SECURE_STORAGE_ITS_CALLER_EXTERNAL,
				      data_length, p_data, create_flags);
}

psa_status_t secure_storage_its_set(psa_storage_uid_t uid, secure_storage_its_caller_id_t caller_id,
				    size_t data_length, const void *p_data,
				    psa_storage_create_flags_t create_flags)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_length, p_data)
	 || !validate_create_flags(create_flags)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	return secure_storage_its_impl_set(ITS_UID, data_length, p_data, create_flags);
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size,
			 void *p_data, size_t *p_data_length)
{
	return secure_storage_its_get(uid, SECURE_STORAGE_ITS_CALLER_EXTERNAL,
				      data_offset, data_size, p_data, p_data_length);
}

psa_status_t secure_storage_its_get(psa_storage_uid_t uid, secure_storage_its_caller_id_t caller_id,
				    size_t data_offset, size_t data_size, void *p_data,
				    size_t *p_data_length)
{
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_size, p_data)
	 || !validate_ptr(p_data_length)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (data_size == 0) {
		*p_data_length = 0;
		return PSA_SUCCESS;
	}

	return secure_storage_its_impl_get(ITS_UID, data_offset, data_size, p_data, p_data_length);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
	return secure_storage_its_get_info(uid, SECURE_STORAGE_ITS_CALLER_EXTERNAL, p_info);
}

psa_status_t secure_storage_its_get_info(psa_storage_uid_t uid,
					 secure_storage_its_caller_id_t caller_id,
					 struct psa_storage_info_t *p_info)
{
	if (!validate_uid(uid)
	 || !validate_ptr(p_info)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	return secure_storage_its_impl_get_info(ITS_UID, p_info);
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

	return secure_storage_its_impl_remove(ITS_UID);
}
