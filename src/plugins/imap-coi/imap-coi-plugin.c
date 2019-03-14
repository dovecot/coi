/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "module-context.h"
#include "coi-common.h"
#include "mail-storage-private.h"
#include "imap-feature.h"
#include "imap-coi-plugin.h"

#define IMAP_COI_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_coi_user_module)
#define IMAP_COI_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, imap_coi_user_module)

struct imap_coi_user {
	union mail_user_module_context module_ctx;
	struct coi_context *coi_ctx;
};

const char *imap_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_coi_module;
static MODULE_CONTEXT_DEFINE_INIT(imap_coi_user_module,
				  &mail_user_module_register);

static imap_client_created_func_t *next_hook_client_created;

static unsigned int imap_feature_coi = UINT_MAX;

static void imap_client_enable_coi(struct client *client)
{
	struct imap_coi_user *icuser = IMAP_COI_USER_CONTEXT(client->user);
	const char *line;

	if (icuser == NULL)
		return;

	line = t_strdup_printf("* COI MAILBOX-ROOT %s",
			       coi_get_mailbox_root(icuser->coi_ctx));
	client_send_line(client, line);
}

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

static void imap_coi_user_deinit(struct mail_user *user)
{
	struct imap_coi_user *icuser = IMAP_COI_USER_CONTEXT_REQUIRE(user);

	coi_context_deinit(&icuser->coi_ctx);
	icuser->module_ctx.super.deinit(user);
}

static void imap_coi_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct imap_coi_user *icuser;

	icuser = p_new(user->pool, struct imap_coi_user, 1);
	icuser->module_ctx.super = *v;
	user->vlast = &icuser->module_ctx.super;

	v->deinit = imap_coi_user_deinit;
	MODULE_CONTEXT_SET(user, imap_coi_user_module, icuser);
}

static void imap_coi_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct imap_coi_user *icuser = IMAP_COI_USER_CONTEXT_REQUIRE(user);

	/* don't set COI context for raw user */
	if (!user->autocreated)
		icuser->coi_ctx = coi_context_init(user);
}

static struct mail_storage_hooks imap_coi_mail_storage_hooks = {
	.mail_user_created = imap_coi_mail_user_created,
	.mail_namespaces_created = imap_coi_mail_namespaces_created,
};

void imap_coi_plugin_init(struct module *module)
{
	imap_coi_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_coi_client_created);

	imap_feature_coi =
		imap_feature_register("COI", 0, imap_client_enable_coi);
	mail_storage_hooks_add(module, &imap_coi_mail_storage_hooks);
}

void imap_coi_plugin_deinit(void)
{
	imap_client_created_hook_set(next_hook_client_created);
	mail_storage_hooks_remove(&imap_coi_mail_storage_hooks);
}

const char *imap_coi_plugin_dependencies[] = { NULL };
const char imap_coi_plugin_binary_dependency[] = "imap";
