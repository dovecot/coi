/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "webpush-vapid.h"
#include "webpush-plugin.h"

const char *webpush_plugin_version = DOVECOT_ABI_VERSION;
const char *push_notification_plugin_dependencies[] = { "push_notification", NULL };

void webpush_plugin_init(struct module *module ATTR_UNUSED)
{
	webpush_vapid_init();
	webpush_device_init();
	webpush_notify_register();
}

void webpush_plugin_deinit(void)
{
	webpush_notify_unregister();
}
