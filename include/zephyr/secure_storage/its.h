/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_ITS_H
#define SECURE_STORAGE_ITS_H

#include <psa/storage_common.h>

psa_status_t secure_storage_its_set(const char *prefix, const psa_storage_uid_t uid,
				    size_t data_length, const void *p_data,
				    psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_its_get(const char *prefix, const psa_storage_uid_t uid,
				    size_t data_offset, size_t data_length, void *p_data,
				    size_t *p_data_length);

psa_status_t secure_storage_its_get_info(const char *prefix, const psa_storage_uid_t uid,
					 struct psa_storage_info_t *p_info);

psa_status_t secure_storage_its_remove(const char *prefix, const psa_storage_uid_t uid);

#endif /* SECURE_STORAGE_ITS_H */
