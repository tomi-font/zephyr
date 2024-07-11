/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_PS_H
#define SECURE_STORAGE_PS_H

#include <psa/storage_common.h>

psa_status_t secure_storage_ps_set(const char *prefix, const psa_storage_uid_t uid,
				   size_t data_length, const void *p_data,
				   psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_ps_get(const char *prefix, const psa_storage_uid_t uid,
				   size_t data_offset, size_t data_length, void *p_data,
				   size_t *p_data_length);

psa_status_t secure_storage_ps_get_info(const char *prefix, const psa_storage_uid_t uid,
					struct psa_storage_info_t *p_info);

psa_status_t secure_storage_ps_remove(const char *prefix, const psa_storage_uid_t uid);

#ifdef CONFIG_SECURE_STORAGE_PSA_PS_SUPPORT_SET_EXTENDED

psa_status_t secure_storage_ps_create(const char *prefix, psa_storage_uid_t uid, size_t capacity,
				      psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_ps_set_extended(const char *prefix, psa_storage_uid_t uid,
					    size_t data_offset, size_t data_length,
					    const void *p_data);

#endif /* CONFIG_SECURE_STORAGE_PSA_PS_SUPPORT_SET_EXTENDED */

#endif /* SECURE_STORAGE_PS_H */
