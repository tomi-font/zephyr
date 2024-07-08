/* SPDX-License-Identifier: Apache-2.0 */

#include <psa/crypto.h>
#include <psa/internal_trusted_storage.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(psa_its);

#define SAMPLE_DATA_UID (psa_storage_uid_t)1
#define SAMPLE_DATA_SIZE 16
#define SAMPLE_DATA_FLAGS PSA_STORAGE_FLAG_NONE

static int read_inexistent_uid(void)
{
	LOG_INF("Verifying that reading an inexistent UID will fail...");
	psa_status_t ret;

	/* Read from the start of the entry. */
	const uint32_t data_offset = 0;

	/* The buffer to which the data read is written. */
	uint8_t p_data[4];

	/* Number of bytes written. */
	size_t p_data_length;

	ret = psa_its_get(SAMPLE_DATA_UID, data_offset, sizeof(p_data), p_data, &p_data_length);
	if (ret != PSA_ERROR_DOES_NOT_EXIST) {
		LOG_ERR("Unexpected psa_its_get() return value. (%d)", ret);
		return -1;
	}

	LOG_INF("Attempting to read an inexistent UID correctly failed.");
	return 0;
}

static int write_and_read_data(void)
{
	LOG_INF("Writing to and reading back from ITS...");
	psa_status_t ret;

	/* Data to be written to ITS. */
	uint8_t p_data_write[SAMPLE_DATA_SIZE];

	memset(p_data_write, 0x42, sizeof(p_data_write));

	ret = psa_its_set(SAMPLE_DATA_UID, sizeof(p_data_write), p_data_write, SAMPLE_DATA_FLAGS);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Writing the data to ITS failed. (%d)", ret);
		return -1;
	}

	/* Data to be read from ITS. */
	uint8_t p_data_read[sizeof(p_data_write)];

	/* Read from the start of the entry. */
	uint32_t data_offset = 0;

	/* Number of bytes read. */
	size_t p_data_length = 0;

	ret = psa_its_get(SAMPLE_DATA_UID, data_offset, sizeof(p_data_read), p_data_read,
			  &p_data_length);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Reading back the data from ITS failed. (%d).", ret);
		return -1;
	}

	if (p_data_length != sizeof(p_data_read)) {
		LOG_ERR("Unexpected amount of bytes read back. (%zu != %zu)",
			p_data_length, sizeof(p_data_read));
		return -1;
	}

	if (memcmp(p_data_write, p_data_read, sizeof(p_data_read))) {
		LOG_HEXDUMP_ERR(p_data_read, sizeof(p_data_read), "Wrong data read back:");
		return -1;
	}

	LOG_INF("Successfully wrote to ITS and read back what was written.");
	return 0;
}

static int read_info(void)
{
	LOG_INF("Verifying the written entry's metadata...");
	psa_status_t ret;

	/* The entry's metadata. */
	struct psa_storage_info_t p_info;

	ret = psa_its_get_info(SAMPLE_DATA_UID, &p_info);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Failed to retrieve the entry's metadata. (%d)", ret);
		return -1;
	}

	if (p_info.capacity != SAMPLE_DATA_SIZE
	 || p_info.size != SAMPLE_DATA_SIZE
	 || p_info.flags != SAMPLE_DATA_FLAGS) {
		LOG_ERR("Entry metadata unexpected. (capacity:%zu size:%zu flags:0x%x)",
			p_info.capacity, p_info.size, p_info.flags);
		return -1;
	}

	LOG_INF("Successfully verified the entry's metadata.");
	return 0;
}

static int remove_entry(void)
{
	LOG_INF("Removing the entry from ITS...");
	psa_status_t ret;

	ret = psa_its_remove(SAMPLE_DATA_UID);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Failed to remove the entry. (%d)", ret);
		return -1;
	}

	LOG_INF("Entry removed from ITS.");
	return 0;
}

int main(void)
{
	LOG_INF("PSA ITS sample started.");

	/* Ensure there is not already an entry with this UID. */
	psa_its_remove(SAMPLE_DATA_UID);

	if (read_inexistent_uid()) {
		return -1;
	}

	if (write_and_read_data()) {
		return -1;
	}

	if (read_info()) {
		return -1;
	}

	if (remove_entry()) {
		return -1;
	}

	LOG_INF("Sample finished successfully.");
	return 0;
}
