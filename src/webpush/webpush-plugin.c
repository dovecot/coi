/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "webpush-plugin.h"

const char *webpush_plugin_version = DOVECOT_ABI_VERSION;

void webpush_plugin_init(struct module *module ATTR_UNUSED)
{
	webpush_vapid_init();
}

void webpush_plugin_deinit(void)
{
}
