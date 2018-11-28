/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "module-context.h"
#include "imap-feature.h"
#include "imap-coi-plugin.h"

#define IMAP_COI_DEFAULT_MAILBOX_ROOT "COI"

const char *imap_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_coi_module;
static imap_client_created_func_t *next_hook_client_created;

static unsigned int imap_feature_coi = UINT_MAX;

static void imap_client_enable_coi(struct client *client)
{
	const char *root;

	root = mail_user_plugin_getenv(client->user, "coi_mailbox_root");
	if (root == NULL)
		root = IMAP_COI_DEFAULT_MAILBOX_ROOT;
	client_send_line(client, t_strdup_printf("* COI MAILBOX-ROOT %s", root));
}

static void imap_coi_client_created(struct client **_client)
{
	struct client *client = *_client;

	if (mail_user_is_plugin_loaded(client->user, imap_coi_module))
		client_add_capability(client, "COI");

	if (next_hook_client_created != NULL)
		next_hook_client_created(_client);
}

void imap_coi_plugin_init(struct module *module)
{
	imap_coi_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_coi_client_created);

	imap_feature_coi =
		imap_feature_register("COI", 0, imap_client_enable_coi);
}

void imap_coi_plugin_deinit(void)
{
	imap_client_created_hook_set(next_hook_client_created);
}

const char *imap_coi_plugin_dependencies[] = { NULL };
const char imap_coi_plugin_binary_dependency[] = "imap";
