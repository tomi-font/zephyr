/*
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/fs/fs.h>
#include <zephyr/mgmt/mcumgr/mgmt/mgmt.h>
#include <zephyr/mgmt/mcumgr/grp/fs_mgmt/fs_mgmt_hash_checksum.h>
#include <string.h>

#include <mgmt/mcumgr/grp/fs_mgmt/fs_mgmt_config.h>
#include <mgmt/mcumgr/grp/fs_mgmt/fs_mgmt_hash_checksum_sha256.h>

#if defined(CONFIG_BUILD_WITH_TFM)
#define PSA_IMPLEMENTATION
#endif

#if defined(PSA_IMPLEMENTATION)
#include <psa/crypto.h>
#define SUCCESS_VALUE PSA_SUCCESS
#else
#include <mbedtls/sha256.h>
#define SUCCESS_VALUE 0
#endif

#define SHA256_DIGEST_SIZE 32

static int fs_mgmt_hash_checksum_sha256(struct fs_file_t *file, uint8_t *output,
					size_t *out_len, size_t len)
{
	int rc = MGMT_ERR_EUNKNOWN;
	int op_ret;
	ssize_t bytes_read = 0;
	size_t read_size = CONFIG_MCUMGR_GRP_FS_CHECKSUM_HASH_CHUNK_SIZE;
	uint8_t buffer[CONFIG_MCUMGR_GRP_FS_CHECKSUM_HASH_CHUNK_SIZE];
#if defined(PSA_IMPLEMENTATION)
	psa_hash_operation_t psa_hash_ctx = psa_hash_operation_init();
#else
	mbedtls_sha256_context mbed_hash_ctx;
#endif

	/* Clear variables prior to calculation */
	*out_len = 0;
	memset(output, 0, SHA256_DIGEST_SIZE);

#if defined(PSA_IMPLEMENTATION)
	if (psa_hash_setup(&psa_hash_ctx, PSA_ALG_SHA_256) != PSA_SUCCESS) {
		return MGMT_ERR_EUNKNOWN;
	}
#else
	mbedtls_sha256_init(&mbed_hash_ctx);
	if (mbedtls_sha256_starts(&mbed_hash_ctx, false) != 0) {
		goto teardown;
	}
#endif

	/* Read all data from file and add to SHA256 hash calculation */
	do {
		if ((read_size + *out_len) >= len) {
			/* Limit read size to size of requested data */
			read_size = len - *out_len;
		}

		bytes_read = fs_read(file, buffer, read_size);

		if (bytes_read < 0) {
			/* Failed to read file data */
			goto teardown;
		} else if (bytes_read > 0) {
#if defined(PSA_IMPLEMENTATION)
			op_ret = psa_hash_update(&psa_hash_ctx, buffer, bytes_read);
#else
			op_ret = mbedtls_sha256_update(&mbed_hash_ctx, buffer, bytes_read);
#endif
			if (op_ret != SUCCESS_VALUE) {
				goto teardown;
			}

			*out_len += bytes_read;
		}
	} while (bytes_read > 0 && *out_len < len);

	/* Finalise SHA256 hash calculation and store output in provided output buffer */
#if defined(PSA_IMPLEMENTATION)
	op_ret = psa_hash_finish(&psa_hash_ctx, output, SHA256_DIGEST_SIZE, &read_size);
#else
	op_ret = mbedtls_sha256_finish(&mbed_hash_ctx, output);
#endif
	if (op_ret == SUCCESS_VALUE) {
		rc = 0;
	}

teardown:
#if defined(PSA_IMPLEMENTATION)
	psa_hash_abort(&psa_hash_ctx);
#else
	mbedtls_sha256_free(&mbed_hash_ctx);
#endif

	return rc;
}

static struct fs_mgmt_hash_checksum_group sha256 = {
	.group_name = "sha256",
	.byte_string = true,
	.output_size = SHA256_DIGEST_SIZE,
	.function = fs_mgmt_hash_checksum_sha256,
};

void fs_mgmt_hash_checksum_register_sha256(void)
{
	fs_mgmt_hash_checksum_register_group(&sha256);
}

void fs_mgmt_hash_checksum_unregister_sha256(void)
{
	fs_mgmt_hash_checksum_unregister_group(&sha256);
}
