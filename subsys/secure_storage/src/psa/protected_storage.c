/* SPDX-License-Identifier: Apache-2.0 */

#include <psa/protected_storage.h>
#ifdef CONFIG_SECURE_STORAGE_PS_IMPLEMENTATION_CUSTOM
#include <zephyr/secure_storage/ps/impl.h>
#else
#include <zephyr/secure_storage/its/internal.h>
#endif
#include "helpers.h"

psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
			psa_storage_create_flags_t create_flags)

{
#ifdef CONFIG_SECURE_STORAGE_PS_IMPLEMENTATION_CUSTOM
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_length, p_data)
	 || !validate_create_flags(create_flags)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_set(uid, data_length, p_data, create_flags);
#else
	return secure_storage_its_set(uid, SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_PS,
				      data_length, p_data, create_flags);
#endif
}

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size, void *p_data,
			size_t *p_data_length)
{
#ifdef CONFIG_SECURE_STORAGE_PS_IMPLEMENTATION_CUSTOM
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_size, p_data)
	 || !validate_ptr(p_data_length)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_get(uid, data_offset, data_size, p_data, p_data_length);
#else
	return secure_storage_its_get(uid, SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_PS,
				      data_offset, data_size, p_data, p_data_length);
#endif
}

psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
#ifdef CONFIG_SECURE_STORAGE_PS_IMPLEMENTATION_CUSTOM
	if (!validate_uid(uid)
	 || !validate_ptr(p_info)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_get_info(uid, p_info);
#else
	return secure_storage_its_get_info(uid, SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_PS, p_info);
#endif
}

psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
#ifdef CONFIG_SECURE_STORAGE_PS_IMPLEMENTATION_CUSTOM
	if (!validate_uid(uid)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_remove(uid);
#else
	return secure_storage_its_remove(uid, SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_PS);
#endif
}

uint32_t psa_ps_get_support(void)
{
	uint32_t flags = 0;

#ifdef CONFIG_SECURE_STORAGE_PS_SUPPORTS_SET_EXTENDED
	flags |= PSA_STORAGE_SUPPORT_SET_EXTENDED;
#endif
	return flags;
}

psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
			   psa_storage_create_flags_t create_flags)
{
#ifdef CONFIG_SECURE_STORAGE_PS_SUPPORTS_SET_EXTENDED
	if (!validate_uid(uid)
	 || !validate_create_flags(create_flags)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_create(uid, capacity, create_flags);
#else
	(void)uid;
	(void)capacity;
	(void)create_flags;
	return PSA_ERROR_NOT_SUPPORTED;
#endif
}

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset, size_t data_length,
				 const void *p_data)
{
#ifdef CONFIG_SECURE_STORAGE_PS_SUPPORTS_SET_EXTENDED
	if (!validate_uid(uid)
	 || !validate_sized_ptr(data_length, p_data)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return secure_storage_ps_impl_set_extended(uid, data_offset, data_length, p_data);
#else
	(void)uid;
	(void)data_offset;
	(void)data_length;
	(void)p_data;
	return PSA_ERROR_NOT_SUPPORTED;
#endif
}
