/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_ITS_INTERNAL_H
#define SECURE_STORAGE_ITS_INTERNAL_H

#include <zephyr/secure_storage/its/common.h>

psa_status_t secure_storage_its_set(psa_storage_uid_t uid, secure_storage_its_caller_id_t caller_id,
				    size_t data_length, const void *p_data,
				    psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_its_get(psa_storage_uid_t uid, secure_storage_its_caller_id_t caller_id,
				    size_t data_offset, size_t data_size, void *p_data,
				    size_t *p_data_length);

psa_status_t secure_storage_its_get_info(psa_storage_uid_t uid,
					 secure_storage_its_caller_id_t caller_id,
					 struct psa_storage_info_t *p_info);

psa_status_t secure_storage_its_remove(psa_storage_uid_t uid,
				       secure_storage_its_caller_id_t caller_id);

#endif
