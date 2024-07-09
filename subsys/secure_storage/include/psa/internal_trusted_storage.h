/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file psa/internal_trusted_storage.h
 * @defgroup psa_its
 * @brief The PSA Internal Trusted Storage (ITS) API.
 * @{
 */
#ifndef PSA_INTERNAL_TRUSTED_STORAGE_H
#define PSA_INTERNAL_TRUSTED_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <psa/storage_common.h>

#define PSA_ITS_API_VERSION_MAJOR 1
#define PSA_ITS_API_VERSION_MINOR 0

/**
 * @brief Creates a new or modifies an existing entry.
 *
 * Stores data in the internal storage.
 *
 * @param uid          The identifier of the data. Must be nonzero.
 * @param data_length  The size in bytes of the data in `p_data` to store.
 * @param p_data       A buffer containing the data to store.
 * @param create_flags The flags that the data will be stored with.
 *
 * @retval PSA_SUCCESS                    The operation completed successfully.
 * @retval PSA_ERROR_NOT_PERMITTED        The provided `uid` has already been created with
 *                                        PSA_STORAGE_FLAG_WRITE_ONCE.
 * @retval PSA_ERROR_NOT_SUPPORTED        One or more flags provided in `create_flags` are not
 *                                        supported or invalid.
 * @retval PSA_ERROR_INVALID_ARGUMENT     One or more arguments other than `create_flags` are
 *                                        invalid.
 * @retval PSA_ERROR_INSUFFICIENT_STORAGE There is insufficient space on the storage medium.
 * @retval PSA_ERROR_STORAGE_FAILURE      The physical storage has failed (fatal error).
 */
psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length, const void *p_data,
			 psa_storage_create_flags_t create_flags);

/**
 * @brief Retrieves data associated with a provided UID.
 *
 * Retrieves up to `data_size` bytes of the data associated with `uid`, starting at `data_offset`
 * bytes from the beginning of the data. Upon successful return the data read will be in the
 * `p_data` buffer, which must be at least `data_size` bytes in size. The length of the data
 * returned will be in `p_data_length`.
 *
 * @param[in]  uid           The identifier of the data.
 * @param[in]  data_offset   The offset, in bytes, from which to start reading the data.
 * @param[in]  data_size     The number of bytes to read.
 * @param[out] p_data        The buffer where the data will be placed on success.
 *                           Must be at least `data_size` bytes long.
 * @param[out] p_data_length On success, the number of bytes placed in `p_data`.
 *
 * @retval PSA_SUCCESS                The operation completed successfully.
 * @retval PSA_ERROR_INVALID_ARGUMENT One or more of the arguments are invalid. This can also
 *                                    happen if `data_offset` is larger than the size of the data
 *                                    associated with `uid`.
 * @retval PSA_ERROR_DOES_NOT_EXIST   The provided `uid` was not found in the storage.
 * @retval PSA_ERROR_STORAGE_FAILURE  The physical storage has failed (fatal error).
 */
psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size, void *p_data,
			 size_t *p_data_length);

/**
 * @brief Retrieves the metadata of a given entry.
 *
 * @param[in]  uid    The identifier of the entry.
 * @param[out] p_info A pointer to a `psa_storage_info_t` struct that will
 *                    be populated with the metadata on success.
 *
 * @retval PSA_SUCCESS                The operation completed successfully.
 * @retval PSA_ERROR_INVALID_ARGUMENT One or more of the arguments are invalid.
 * @retval PSA_ERROR_DOES_NOT_EXIST   The provided `uid` was not found in the storage.
 * @retval PSA_ERROR_STORAGE_FAILURE  The physical storage has failed (fatal error).
 */
psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info);

/**
 * @brief Removes the entry associated with the provided UID.
 *
 * Deletes all the data associated with the entry from internal storage.
 *
 * @param uid The identifier of the entry to remove.
 *
 * @retval PSA_SUCCESS                The operation completed successfully.
 * @retval PSA_ERROR_NOT_PERMITTED    The entry was created with PSA_STORAGE_FLAG_WRITE_ONCE.
 * @retval PSA_ERROR_INVALID_ARGUMENT `uid` is invalid.
 * @retval PSA_ERROR_DOES_NOT_EXIST   The provided `uid` was not found in the storage.
 * @retval PSA_ERROR_STORAGE_FAILURE  The physical storage has failed (fatal error).
 */
psa_status_t psa_its_remove(psa_storage_uid_t uid);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* PSA_INTERNAL_TRUSTED_STORAGE_H */
