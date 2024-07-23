/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SECURE_STORAGE_ITS_COMMON_H
#define SECURE_STORAGE_ITS_COMMON_H

#include <zephyr/toolchain.h>
#include <psa/storage_common.h>

typedef enum {
	SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_ITS,
	SECURE_STORAGE_ITS_CALLER_ZEPHYR_PSA_PS,
	SECURE_STORAGE_ITS_CALLER_EXTERNAL,
} secure_storage_its_caller_id_t;

typedef struct {
	psa_storage_uid_t uid;
	secure_storage_its_caller_id_t caller_id;
} __packed secure_storage_its_uid_t;

#endif
