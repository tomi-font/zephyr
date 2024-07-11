/* SPDX-License-Identifier: Apache-2.0 */

#ifndef HELPERS_H
#define HELPERS_H

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

#endif
