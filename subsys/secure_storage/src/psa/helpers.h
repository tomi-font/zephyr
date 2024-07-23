/* SPDX-License-Identifier: Apache-2.0 */

#ifndef HELPERS_H
#define HELPERS_H

#include <psa/storage_common.h>
#include <stdbool.h>

static inline bool validate_uid(psa_storage_uid_t uid)
{
	return (uid != 0);
}

static inline bool validate_ptr(const void *ptr)
{
	return (ptr != NULL);
}

static inline bool validate_sized_ptr(size_t size, const void *ptr)
{
	return (size == 0 || ptr != NULL);
}

static inline bool validate_create_flags(psa_storage_create_flags_t create_flags)
{
	return !(create_flags & ~(PSA_STORAGE_FLAG_NONE |
				  PSA_STORAGE_FLAG_WRITE_ONCE |
				  PSA_STORAGE_FLAG_NO_CONFIDENTIALITY |
				  PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION));
}

#endif
