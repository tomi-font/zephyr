# SPDX-License-Identifier: Apache-2.0

zephyr_sources_ifdef(CONFIG_SECURE_STORAGE_ITS_IMPLEMENTATION_DEFAULT
	impl.c
)
zephyr_sources_ifdef(CONFIG_SECURE_STORAGE_ITS_SECURING_MODULE
	securing.c
)
zephyr_sources_ifdef(CONFIG_SECURE_STORAGE_ITS_STORING_IMPLEMENTATION_SETTINGS
	storing_settings.c
)
