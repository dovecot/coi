/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "module-context.h"
#include "mail-user.h"
#include "smtp-address.h"
#include "lmtp-recipient.h"
#include "lmtp-coi-plugin.h"

#include "coi-common.h"

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
lmtp_coi_client_store_chat(struct lmtp_recipient *lrcpt,
			   struct smtp_server_cmd_ctx *cmd,
			   struct smtp_server_transaction *trans,
			   struct lmtp_local_deliver_context *lldctx,
			   struct coi_context *coi_ctx)
{
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	enum mailbox_transaction_flags trans_flags;
	struct mailbox_transaction_context *mtrans;
	struct mail_save_context *save_ctx;
	struct smtp_address *rcpt_to = rcpt->path;
	unsigned int rcpt_idx = rcpt->index;
	struct mailbox *box;
	struct mail_storage *storage;
	int ret = 0;

	if (coi_mailbox_chats_open(coi_ctx, MAILBOX_FLAG_SAVEONLY |
					    MAILBOX_FLAG_POST_SESSION,
				   &box, &storage) < 0) {
		smtp_server_reply_index(
			cmd, rcpt_idx, 451, "4.2.0",
			"<%s> Failed to save chat message: %s",
			smtp_address_encode(rcpt_to),
			mail_storage_get_last_error(storage, NULL));
		return -1;
	}

	trans_flags = MAILBOX_TRANSACTION_FLAG_EXTERNAL;
	mtrans = mailbox_transaction_begin(box, trans_flags, __func__);
	save_ctx = mailbox_save_alloc(mtrans);
	if (trans->mail_from != NULL) {
		mailbox_save_set_from_envelope(save_ctx,
			smtp_address_encode(trans->mail_from));
	}

	if (mailbox_save_using_mail(&save_ctx, lldctx->src_mail) < 0)
		ret = -1;

	if (ret < 0)
		mailbox_transaction_rollback(&mtrans);
	else
		ret = mailbox_transaction_commit(&mtrans);

	if (ret < 0) {
		i_error("COI: Failed to save message to chats mailbox `%s': %s",
			mailbox_get_vname(box),
			mail_storage_get_last_internal_error(storage, NULL));
		smtp_server_reply_index(
			cmd, rcpt_idx, 451, "4.2.0",
			"<%s> Failed to save chat message: %s",
			smtp_address_encode(rcpt_to),
			mail_storage_get_last_error(storage, NULL));
	} else {
		i_info("COI: Saved message to chats mailbox `%s'",
		       mailbox_get_vname(box));
		smtp_server_reply_index(cmd, rcpt_idx,
			250, "2.0.0", "<%s> %s Saved chat message",
			smtp_address_encode(rcpt_to), lldctx->session_id);
	}

	mailbox_free(&box);
	return ret;
}

static int
lmtp_coi_client_local_deliver(struct client *client,
			      struct lmtp_recipient *lrcpt,
			      struct smtp_server_cmd_ctx *cmd,
			      struct smtp_server_transaction *trans,
			      struct lmtp_local_deliver_context *lldctx)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);
	struct lmtp_coi_recipient *lcrcpt = LMTP_COI_RCPT_CONTEXT(lrcpt);
	struct coi_context *coi_ctx = NULL;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct mail_user *user = lldctx->rcpt_user;
	const char *header;

	if (lcrcpt != NULL) {
		/* Handle COI recipient delivery (RCPT command with tokens) */
		i_debug("coi: Delivering for COI recipient `%s'",
			smtp_address_encode(rcpt->path));

		coi_ctx = coi_context_init(user);

		// FIXME: do COI magic stuff?
	} else if (mail_get_first_header(lldctx->src_mail, COI_MSGHDR_CHAT,
					 &header) > 0) {
		/* Message has COI chat header */
		coi_ctx = coi_context_init(user);
	} else {
		coi_ctx = coi_context_init(user);
		if (coi_mail_is_chat_related(coi_ctx, lldctx->src_mail) <= 0) {
			/* Message has no references to chat messages */
			coi_context_deinit(&coi_ctx);
		}
	}

	if (coi_ctx != NULL) {
		int ret;

		/* Save it as a chat message only */
		ret = lmtp_coi_client_store_chat(lrcpt, cmd, trans, lldctx,
						 coi_ctx);
		coi_context_deinit(&coi_ctx);
		return ret;
	}

	return lcclient->super.local_deliver(client, lrcpt, cmd, trans, lldctx);
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
