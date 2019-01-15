/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "module-context.h"
#include "mail-user.h"
#include "smtp-address.h"
#include "lmtp-recipient.h"
#include "lmtp-coi-plugin.h"

#define LMTP_COI_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_client_module)
#define LMTP_COI_RCPT_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_recipient_module)

struct lmtp_coi_recipient;
struct lmtp_coi_backend;
struct lmtp_coi_client;

// FIXME: Debugging messages in this plugin need to use events

struct lmtp_coi_recipient {
	union lmtp_recipient_module_context module_ctx;
	struct lmtp_recipient *rcpt;

	struct lmtp_coi_recipient *next;

	const char *token, *my_token;
};

struct lmtp_coi_client {
	union lmtp_module_context module_ctx;
	struct lmtp_client_vfuncs super;
	struct client *client;

	struct {
		struct lmtp_coi_recipient *rcpts;
	} trans_state;
};

const char *lmtp_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *lmtp_coi_module;
static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_client_module,
				  &lmtp_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_recipient_module,
				  &lmtp_recipient_module_register);

static lmtp_client_created_func_t *next_hook_client_created;

static void
lmtp_coi_client_destroy(struct client *client, const char *enh_code,
			const char *reason)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);

	// FIXME

	lcclient->super.destroy(client, enh_code, reason);
}

static void
lmtp_coi_client_trans_free(struct client *client,
			   struct smtp_server_transaction *trans)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);

	i_debug("coi: Transaction free");

	i_zero(&lcclient->trans_state);

	lcclient->super.trans_free(client, trans);
}

static int
lmtp_coi_client_cmd_mail(struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_cmd_mail *data)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);

	i_debug("coi: MAIL command");

	// FIXME: anything?

	return lcclient->super.cmd_mail(client, cmd, data);
}

static int
lmtp_coi_cmd_rcpt_chat(struct lmtp_coi_client *lcclient,
		       struct lmtp_recipient *lrcpt,
		       const char *my_token, const char *token)
{
	struct client *client = lcclient->client;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct smtp_server_cmd_ctx *cmd = rcpt->cmd;
	struct lmtp_coi_recipient *lcrcpt;

	i_debug("coi: RCPT command: This is a chat recipient");

	lcrcpt = p_new(rcpt->pool, struct lmtp_coi_recipient, 1);
	MODULE_CONTEXT_SET(lrcpt, lmtp_coi_recipient_module, lcrcpt);
	lcrcpt->rcpt = lrcpt;

	lcrcpt->token = p_strdup(rcpt->pool, token);
	lcrcpt->my_token = p_strdup(rcpt->pool, my_token);

	lcrcpt->next = lcclient->trans_state.rcpts;
	lcclient->trans_state.rcpts = lcrcpt;

	return lcclient->super.cmd_rcpt(client, cmd, lrcpt);
}

static int
lmtp_coi_client_cmd_rcpt(struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct lmtp_recipient *lrcpt)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	const char *token, *my_token, *param;

	token = my_token = NULL;
	if (smtp_params_rcpt_drop_extra(&rcpt->params, "TOKEN", &param)) {
		if (param == NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Missing TOKEN= parameter value");
			return -1;
		}
		token = param;
	}
	if (smtp_params_rcpt_drop_extra(&rcpt->params, "MYTOKEN", &param)) {
		if (param == NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Missing MYTOKEN= parameter value");
			return -1;
		}
		my_token = param;
	}

	if (token == NULL && my_token == NULL) {
		/* This is a normal recipient */

		// Delivered through default backend.
	} else if (token == NULL || my_token == NULL) {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "The TOKEN= and MYTOKEN= parameters are both required");
		return -1;
	} else {
		/* This is a chat recipient */
		return lmtp_coi_cmd_rcpt_chat(lcclient, lrcpt, my_token, token);
	}

	i_debug("coi: RCPT command: This ia a normal recipient");
	return lcclient->super.cmd_rcpt(client, cmd, lrcpt);
}

static int
lmtp_coi_client_local_deliver(struct client *client,
			      struct lmtp_recipient *lrcpt,
			      struct mail_deliver_context *dctx,
			      struct mail_storage **storage_r)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);
	struct lmtp_coi_recipient *lcrcpt = LMTP_COI_RCPT_CONTEXT(lrcpt);
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;

	if (lcrcpt != NULL) {
		/* Handle COI recipient delivery */
		i_debug("coi: Delivering for COI recipient `%s'",
			smtp_address_encode(rcpt->path));

		// FIXME: do COI magic stuff
	}

	return lcclient->super.local_deliver(client, lrcpt, dctx, storage_r);
}

static void lmtp_coi_client_create(struct client *client)
{
	struct lmtp_coi_client *lcclient;
	struct smtp_capability_extra extra_cap;

	i_debug("coi: Client create");

	lcclient = p_new(client->pool, struct lmtp_coi_client, 1);
	MODULE_CONTEXT_SET(client, lmtp_coi_client_module, lcclient);
	lcclient->client = client;

	lcclient->super = client->v;
	client->v.destroy = lmtp_coi_client_destroy;
	client->v.trans_free = lmtp_coi_client_trans_free;
	client->v.cmd_mail = lmtp_coi_client_cmd_mail;
	client->v.cmd_rcpt = lmtp_coi_client_cmd_rcpt;
	client->v.local_deliver = lmtp_coi_client_local_deliver;

	i_zero(&extra_cap);
	extra_cap.name = "COI"; // FIXME: better name for this protocol
	smtp_server_connection_add_extra_capability(client->conn, &extra_cap);

	smtp_server_connection_register_rcpt_param(client->conn, "TOKEN");
	smtp_server_connection_register_rcpt_param(client->conn, "MYTOKEN");
}

static void lmtp_coi_client_created(struct client **_client)
{
	struct client *client = *_client;

	lmtp_coi_client_create(client);

	if (next_hook_client_created != NULL)
		next_hook_client_created(_client);
}

void lmtp_coi_plugin_init(struct module *module)
{
	i_debug("coi: Plugin init");

	lmtp_coi_module = module;
	next_hook_client_created =
		lmtp_client_created_hook_set(
			lmtp_coi_client_created);
}

void lmtp_coi_plugin_deinit(void)
{
	i_debug("coi: Plugin deinit");

	lmtp_client_created_hook_set(next_hook_client_created);
}

const char *lmtp_coi_plugin_dependencies[] = { NULL };
const char lmtp_coi_plugin_binary_dependency[] = "lmtp";
