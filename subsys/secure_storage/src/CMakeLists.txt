# SPDX-License-Identifier: Apache-2.0

zephyr_sources_ifdef(CONFIG_TRUSTED_STORAGE_STORAGE_BACKEND_SETTINGS
	storage_backend_settings.c
)

add_subdirectory(psa)

add_subdirectory_ifdef(CONFIG_TRUSTED_STORAGE_BACKEND_AEAD aead)
