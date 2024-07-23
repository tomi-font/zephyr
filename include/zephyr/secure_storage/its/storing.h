#ifndef SECURE_STORAGE_ITS_STORING_H
#define SECURE_STORAGE_ITS_STORING_H

#include <zephyr/secure_storage/its/common.h>

psa_status_t secure_storage_its_storing_set(secure_storage_its_uid_t uid, size_t data_length,
					    const void *data);

psa_status_t secure_storage_its_storing_get(secure_storage_its_uid_t uid, size_t data_size,
					    void *data, size_t *data_length);

psa_status_t secure_storage_its_storing_remove(secure_storage_its_uid_t uid);

#endif
