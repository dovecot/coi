/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "module-context.h"
#include "coi-common.h"
#include "imap-feature.h"
#include "imap-coi-plugin.h"

#define IMAP_COI_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_coi_client_module)

struct imap_coi_client {
	union imap_module_context module_ctx;
	struct imap_client_vfuncs super;
	struct client *client;

	struct coi_context *coi_ctx;
};

const char *imap_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_coi_module;
static MODULE_CONTEXT_DEFINE_INIT(imap_coi_client_module,
				  &imap_module_register);

static imap_client_created_func_t *next_hook_client_created;

static unsigned int imap_feature_coi = UINT_MAX;

static void imap_client_enable_coi(struct client *client)
{
	struct imap_coi_client *icclient = IMAP_COI_CONTEXT(client);
	const char *line;

	if (icclient == NULL)
		return;

	line = t_strdup_printf("* COI MAILBOX-ROOT %s",
			       coi_get_mailbox_root(icclient->coi_ctx));
	client_send_line(client, line);
}

static void
imap_coi_client_init(struct client *client)
{
	struct imap_coi_client *icclient = IMAP_COI_CONTEXT(client);

	icclient->coi_ctx = coi_context_init(client->user);

	icclient->super.init(client);
}

static void
imap_coi_client_destroy(struct client *client, const char *reason)
{
	struct imap_coi_client *icclient = IMAP_COI_CONTEXT(client);

	coi_context_deinit(&icclient->coi_ctx);

	icclient->super.destroy(client, reason);
}

static void imap_coi_client_create(struct client *client)
{
	struct imap_coi_client *icclient;

	icclient = p_new(client->pool, struct imap_coi_client, 1);
	MODULE_CONTEXT_SET(client, imap_coi_client_module, icclient);
	icclient->client = client;

	icclient->super = client->v;
	client->v.init = imap_coi_client_init;
	client->v.destroy = imap_coi_client_destroy;

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

	imap_feature_coi =
		imap_feature_register("COI", 0, imap_client_enable_coi);
}

void imap_coi_plugin_deinit(void)
{
	imap_client_created_hook_set(next_hook_client_created);
}

const char *imap_coi_plugin_dependencies[] = { NULL };
const char imap_coi_plugin_binary_dependency[] = "imap";
