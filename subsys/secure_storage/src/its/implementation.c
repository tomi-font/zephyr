/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/secure_storage/its/implementation.h>

psa_status_t secure_storage_its_impl_set(psa_storage_uid_t uid, size_t data_length,
					 const void *p_data,
					 psa_storage_create_flags_t create_flags,
					 secure_storage_its_caller_id_t caller_id)
{
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t secure_storage_its_impl_get(psa_storage_uid_t uid, size_t data_offset,
					 size_t data_size, void *p_data, size_t *p_data_length,
					 secure_storage_its_caller_id_t caller_id)
{
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t secure_storage_its_impl_get_info(psa_storage_uid_t uid,
					      struct psa_storage_info_t *p_info,
					      secure_storage_its_caller_id_t caller_id)
{
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t secure_storage_its_impl_remove(psa_storage_uid_t uid,
					    secure_storage_its_caller_id_t caller_id)
{
	return PSA_ERROR_NOT_SUPPORTED;
}
