/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_ITS_IMPL_H
#define SECURE_STORAGE_ITS_IMPL_H

#include <zephyr/secure_storage/its/common.h>

psa_status_t secure_storage_its_impl_set(secure_storage_its_uid_t uid, size_t data_length,
					 const void *p_data,
					 psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_its_impl_get(secure_storage_its_uid_t uid, size_t data_offset,
					 size_t data_size, void *p_data, size_t *p_data_length);

psa_status_t secure_storage_its_impl_get_info(secure_storage_its_uid_t uid,
					      struct psa_storage_info_t *p_info);

psa_status_t secure_storage_its_impl_remove(secure_storage_its_uid_t uid);

#endif
