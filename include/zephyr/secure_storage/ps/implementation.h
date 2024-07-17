/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_PS_IMPLEMENTATION_H
#define SECURE_STORAGE_PS_IMPLEMENTATION_H

#include <psa/storage_common.h>

psa_status_t secure_storage_ps_impl_set(const psa_storage_uid_t uid, size_t data_length,
					const void *p_data,
					psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_ps_impl_get(const psa_storage_uid_t uid, size_t data_offset,
					size_t data_length, void *p_data, size_t *p_data_length);

psa_status_t secure_storage_ps_impl_get_info(const psa_storage_uid_t uid,
					     struct psa_storage_info_t *p_info);

psa_status_t secure_storage_ps_impl_remove(const psa_storage_uid_t uid);

#ifdef CONFIG_SECURE_STORAGE_PSA_PS_SUPPORTS_SET_EXTENDED

psa_status_t secure_storage_ps_impl_create(psa_storage_uid_t uid, size_t capacity,
					   psa_storage_create_flags_t create_flags);

psa_status_t secure_storage_ps_impl_set_extended(psa_storage_uid_t uid, size_t data_offset,
						 size_t data_length, const void *p_data);

#endif /* CONFIG_SECURE_STORAGE_PSA_PS_SUPPORTS_SET_EXTENDED */

#endif /* SECURE_STORAGE_PS_IMPLEMENTATION_H */
