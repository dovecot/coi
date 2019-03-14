/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "module-context.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "smtp-address.h"
#include "lmtp-recipient.h"
#include "lmtp-coi-plugin.h"

#include "coi-config.h"
#include "coi-common.h"

#define LMTP_COI_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_client_module)
#define LMTP_COI_RCPT_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_recipient_module)

#define LMTP_COI_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lmtp_coi_storage_module)
#define LMTP_COI_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_mail_module)

struct lmtp_coi_recipient;
struct lmtp_coi_backend;
struct lmtp_coi_client;

// FIXME: Debugging messages in this plugin need to use events

struct lmtp_coi_mail {
	union mail_module_context module_ctx;
	bool add_has_chat_flag;
};

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
static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_mail_module, &mail_module_register);

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
			   struct coi_context *coi_ctx,
			   const char **client_error_r)
{
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	enum mailbox_transaction_flags trans_flags;
	struct mailbox_transaction_context *mtrans;
	struct mail_save_context *save_ctx;
	struct mailbox *box;
	struct mail_storage *storage;
	struct coi_config config;
	int ret = 0;

	if (coi_config_read(coi_ctx, &config) < 0) {
		*client_error_r = "Failed to read COI configuration";
		return -1;
	}
	switch (config.filter) {
	case COI_CONFIG_FILTER_NONE:
		/* store to INBOX */
		return 1;
	case COI_CONFIG_FILTER_ACTIVE:
		break;
	case COI_CONFIG_FILTER_READ: {
		/* For now store to INBOX, but move to Chats when \Seen flag
		   is set. Add $HasChat keyword so IMAP plugin can do this
		   efficiently. */
		struct mail_private *pmail =
			container_of(lldctx->src_mail, struct mail_private, mail);
		struct lmtp_coi_mail *lcmail = LMTP_COI_MAIL_CONTEXT(pmail);

		if (lcmail == NULL) {
			lcmail = p_new(pmail->pool, struct lmtp_coi_mail, 1);
			MODULE_CONTEXT_SET(pmail, lmtp_coi_mail_module, lcmail);
		}
		lcmail->add_has_chat_flag = TRUE;
		return 1;
	}
	}

	if (coi_mailbox_open(coi_ctx, COI_MAILBOX_CHATS,
			     MAILBOX_FLAG_AUTO_CREATE |
			     MAILBOX_FLAG_SAVEONLY | MAILBOX_FLAG_POST_SESSION,
			     &box, &storage) <= 0) {
		*client_error_r = mail_storage_get_last_error(storage, NULL);
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
		*client_error_r = mail_storage_get_last_error(storage, NULL);
	} else {
		i_info("COI: Saved message to chats mailbox `%s'",
		       mailbox_get_vname(box));
		smtp_server_reply_index(cmd, rcpt->index,
			250, "2.0.0", "<%s> %s Saved chat message",
			smtp_address_encode(rcpt->path), lldctx->session_id);
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
	struct coi_context *coi_ctx = NULL;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct mail_user *user = lldctx->rcpt_user;
	const char *header, *client_error;
	int ret;

	coi_ctx = coi_context_init(user);
	if (mail_get_first_header(lldctx->src_mail, COI_MSGHDR_CHAT, &header) > 0 ||
	    coi_mail_is_chat_related(coi_ctx, lldctx->src_mail) > 0) {
		/* This is a chat message */
		ret = lmtp_coi_client_store_chat(lrcpt, cmd, trans, lldctx,
						 coi_ctx, &client_error);
		if (ret < 0) {
			smtp_server_reply_index(
				cmd, rcpt->index, 451, "4.2.0",
				"<%s> Failed to save chat message: %s",
				smtp_address_encode(rcpt->path), client_error);
			ret = -1;
		}
	} else {
		ret = 1;
	}
	coi_context_deinit(&coi_ctx);

	return ret <= 0 ? ret :
		lcclient->super.local_deliver(client, lrcpt, cmd, trans, lldctx);
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

static int
lmtp_coi_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	union mailbox_module_context *lcbox = LMTP_COI_STORAGE_CONTEXT(t->box);
	struct mail_private *pmail =
		container_of(mail, struct mail_private, mail);
	struct lmtp_coi_mail *lcmail = LMTP_COI_MAIL_CONTEXT(pmail);

	if (lcmail != NULL && lcmail->add_has_chat_flag) {
		const char *const chat_kw_arr[] = { COI_KEYWORD_HASCHAT, NULL };
		struct mail_keywords *chat_kw;

		chat_kw = mailbox_keywords_create_valid(t->box, chat_kw_arr);
		if (ctx->data.keywords == NULL)
			ctx->data.keywords = chat_kw;
		else {
			struct mail_keywords *old_kw = ctx->data.keywords;
			ctx->data.keywords = mailbox_keywords_merge(old_kw, chat_kw);
			mailbox_keywords_unref(&old_kw);
			mailbox_keywords_unref(&chat_kw);
		}
	}

	return lcbox->super.copy(ctx, mail);
}

static void lmtp_coi_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *lcbox;

	lcbox = p_new(box->pool, union mailbox_module_context, 1);
	lcbox->super = *v;
	box->vlast = &lcbox->super;

	v->copy = lmtp_coi_copy;
	MODULE_CONTEXT_SET_SELF(box, lmtp_coi_storage_module, lcbox);
}

static struct mail_storage_hooks lmtp_coi_mail_storage_hooks = {
	.mailbox_allocated = lmtp_coi_mailbox_allocated,
};

void lmtp_coi_plugin_init(struct module *module)
{
	i_debug("coi: Plugin init");

	lmtp_coi_module = module;
	next_hook_client_created =
		lmtp_client_created_hook_set(
			lmtp_coi_client_created);
	mail_storage_hooks_add(module, &lmtp_coi_mail_storage_hooks);
}

void lmtp_coi_plugin_deinit(void)
{
	i_debug("coi: Plugin deinit");

	lmtp_client_created_hook_set(next_hook_client_created);
	mail_storage_hooks_remove(&lmtp_coi_mail_storage_hooks);
}

const char *lmtp_coi_plugin_dependencies[] = { NULL };
const char lmtp_coi_plugin_binary_dependency[] = "lmtp";
