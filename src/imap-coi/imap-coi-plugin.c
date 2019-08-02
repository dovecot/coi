/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "coi-common.h"
#include "coi-storage.h"
#include "imap-feature.h"
#include "imap-coi-plugin.h"

const char *imap_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_coi_module;
static imap_client_created_func_t *next_hook_client_created;

static void imap_coi_client_create(struct client *client)
{
	client_add_capability(client, "COI");
}

static void imap_coi_client_created(struct client **_client)
{
	struct client *client = *_client;

	if (mail_user_is_plugin_loaded(client->user, imap_coi_module))
		imap_coi_client_create(client);

	if (next_hook_client_created != NULL)
		next_hook_client_created(_client);
}

void imap_coi_plugin_init(struct module *module)
{
	imap_coi_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_coi_client_created);

	imap_coi_storage_init(module);
	coi_storage_plugin_init(module);
}

void imap_coi_plugin_deinit(void)
{
	imap_client_created_hook_set(next_hook_client_created);
	coi_storage_plugin_deinit();
	imap_coi_storage_deinit();
}

const char *imap_coi_plugin_dependencies[] = { NULL };
const char imap_coi_plugin_binary_dependency[] = "imap";
