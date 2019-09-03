/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "str.h"
#include "module-context.h"
#include "lmtp-recipient.h"
#include "mail-storage.h"
#include "coi-common.h"
#include "coi-storage.h"
#include "coi-secret.h"
#include "coi-contact.h"
#include "coi-contact-list.h"
#include "lmtp-coi-plugin.h"

#ifdef BUILD_UNFINISHED

#define LMTP_COI_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_client_module)
#define LMTP_COI_RCPT_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_recipient_module)

struct lmtp_coi_recipient;
struct lmtp_coi_backend;
struct lmtp_coi_client;

struct lmtp_coi_recipient {
	union lmtp_recipient_module_context module_ctx;
	struct lmtp_recipient *rcpt;

	struct lmtp_coi_recipient *next;

	struct coi_token *token, *my_token;
	const char *reply_token;
	const char *to_normalized;

	/* received token was validated using temporary secrets */
	bool temp_token;
};

struct lmtp_coi_client {
	union lmtp_module_context module_ctx;
	struct lmtp_client_vfuncs super;
	struct client *client;

	struct coi_secret_settings secret_set;

	struct {
		char *from_normalized;
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
lmtp_coi_client_data_reply(struct smtp_server_recipient *rcpt,
			   struct lmtp_coi_recipient *lcrcpt);

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

	i_free(lcclient->trans_state.from_normalized);
	i_zero(&lcclient->trans_state);

	lcclient->super.trans_free(client, trans);
}

static int
lmtp_coi_client_cmd_mail(struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_cmd_mail *data)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);

	i_free(lcclient->trans_state.from_normalized);
	lcclient->trans_state.from_normalized =
		i_strdup(coi_normalize_smtp_address(data->path));

	return lcclient->super.cmd_mail(client, cmd, data);
}

static int
lmtp_coi_cmd_rcpt_chat(struct lmtp_coi_client *lcclient,
		       struct lmtp_recipient *lrcpt,
		       struct coi_token *token, bool temp_token,
		       struct coi_token *my_token)
{
	struct client *client = lcclient->client;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct smtp_server_cmd_ctx *cmd = rcpt->cmd;
	struct lmtp_coi_recipient *lcrcpt;

	lcrcpt = p_new(rcpt->pool, struct lmtp_coi_recipient, 1);
	MODULE_CONTEXT_SET(lrcpt, lmtp_coi_recipient_module, lcrcpt);
	lcrcpt->rcpt = lrcpt;

	lcrcpt->token = token;
	lcrcpt->my_token = my_token;
	lcrcpt->temp_token = temp_token;
	lcrcpt->to_normalized =
		p_strdup(rcpt->pool, coi_normalize_smtp_address(rcpt->path));

	lcrcpt->next = lcclient->trans_state.rcpts;
	lcclient->trans_state.rcpts = lcrcpt;

	smtp_server_recipient_add_hook(rcpt,
				       SMTP_SERVER_RECIPIENT_HOOK_DATA_REPLIED,
				       lmtp_coi_client_data_reply, lcrcpt);

	return lcclient->super.cmd_rcpt(client, cmd, lrcpt);
}

static int
lmtp_coi_client_cmd_rcpt(struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct lmtp_recipient *lrcpt)
{
	struct lmtp_coi_client *lcclient = LMTP_COI_CONTEXT(client);
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct coi_token *parsed_token, *my_parsed_token = NULL;
	const char *token, *my_token, *param, *error;
	bool temp_token;

	token = my_token = NULL;
	if (smtp_params_rcpt_drop_extra(&rcpt->params, "STOKEN", &param)) {
		if (param == NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Missing STOKEN= parameter value");
			return -1;
		}
		token = param;
	}
	if (smtp_params_rcpt_drop_extra(&rcpt->params, "MYSTOKEN", &param)) {
		if (param == NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Missing MYSTOKEN= parameter value");
			return -1;
		}
		my_token = param;
	}

	if (token == NULL && my_token == NULL) {
		/* This is a normal recipient */

		// Delivered through default backend.
	} else if (token == NULL) {
		smtp_server_reply(cmd, 501, "5.5.4",
			"The MYSTOKEN= parameter can't be used without STOKEN parameter");
		return -1;
	} else if (coi_token_parse(token, rcpt->pool,
				   &parsed_token, &error) < 0) {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Couldn't parse STOKEN: %s", error);
		return -1;
	} else if (my_token != NULL &&
		   coi_token_parse(my_token, rcpt->pool,
				   &my_parsed_token, &error) < 0) {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Couldn't parse MYSTOKEN: %s", error);
		return -1;
	} else if (!coi_token_verify_quick(&lcclient->secret_set, time(NULL),
					   parsed_token, &temp_token, &error)) {
		/* The token can't be valid. Don't accept it. */
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Invalid STOKEN: %s", error);
		return -1;
	} else {
		/* This is a chat recipient */
		const char *hash = coi_contact_generate_hash(
			lcclient->trans_state.from_normalized,
			coi_normalize_smtp_address(rcpt->path));
		if (strcmp(parsed_token->from_to_normalized_hash, hash) != 0) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"Invalid STOKEN: from/to address pair doesn't match token's hash");
			return -1;
		}

		return lmtp_coi_cmd_rcpt_chat(lcclient, lrcpt, parsed_token,
					      temp_token, my_parsed_token);
	}

	return lcclient->super.cmd_rcpt(client, cmd, lrcpt);
}

static int
lmtp_coi_client_store_chat(struct lmtp_recipient *lrcpt,
			   struct smtp_server_transaction *trans,
			   struct lmtp_local_deliver_context *lldctx,
			   struct coi_context *coi_ctx,
			   const char **client_error_r)
{
	int ret;

	ret = lmtp_coi_message_filter_save_chat(coi_ctx, lldctx->src_mail,
						trans->mail_from, client_error_r);
	if (ret > 0) {
		smtp_server_recipient_reply(lrcpt->rcpt, 250, "2.0.0",
					    "%s Saved chat message",
					    lldctx->session_id);
	}
	return ret;
}

static bool
lmtp_generate_perm_token(struct lmtp_coi_recipient *lcrcpt,
			 struct coi_token **token_r)
{
	struct lmtp_coi_client *lcclient =
		LMTP_COI_CONTEXT(lcrcpt->rcpt->client);
	struct coi_token *token;

	if (lcclient->secret_set.perm_secrets == NULL ||
	    lcclient->secret_set.perm_secrets[0] == NULL) {
		*token_r = NULL;
		return FALSE;
	}

	token = coi_token_new(pool_datastack_create());
	token->create_time = time(NULL);
	token->validity_secs = COI_PERM_TOKEN_VALIDITY_SECS;
	token->from_to_normalized_hash =
		coi_contact_generate_hash(lcclient->trans_state.from_normalized,
					  lcrcpt->to_normalized);

	string_t *token_string = t_str_new(128);
	/* Append all of the token, except use empty secret. This way the
	   token ends with "secret:" */
	token->secret = "";
	coi_token_append(token_string, token);

	string_t *secret = t_str_new(128);
	/* append the actual secret */
	coi_secret_append(secret, str_c(token_string),
			  lcclient->secret_set.perm_secrets[0]);
	token->secret = str_c(secret);

	str_append_str(token_string, secret);
	token->token_string = str_c(token_string);

	*token_r = token;
	return TRUE;
}

static int
lmtp_coi_update_contact(struct coi_contact_transaction **coi_trans,
			struct coi_contact *used_token_contact,
			struct coi_token *used_token,
			struct lmtp_coi_recipient *lcrcpt,
			const char *from_normalized)
{
	struct mail_storage *error_storage;
	struct mailbox *contact_box;
	struct coi_contact *latest_contact;
	struct coi_token *latest_token;
	struct coi_contact_update *update;

	/* With temporary tokens used_token_contact is NULL.
	   With permanent tokens used_token_contact points to the mail that
	   contained the received token. Normally this is the only contact mail
	   for the sender, but since there's no locking for updates, there can
	   be race conditions. So find again the latest contact mail for the
	   sender. */
	if (coi_contact_list_find(*coi_trans, from_normalized,
				  lcrcpt->to_normalized, &latest_contact,
				  &error_storage) < 0) {
		i_error("Failed to lookup COI contact: %s",
			mail_storage_get_last_internal_error(error_storage, NULL));
		return -1;
	}

	contact_box = coi_contact_transaction_get_mailbox(*coi_trans);
	update = latest_contact != NULL ?
		coi_contact_update_begin(latest_contact->mail) :
		coi_contact_create_begin(contact_box, from_normalized);

	if (used_token_contact != NULL && latest_contact != NULL &&
	    latest_contact->mail->uid != used_token_contact->mail->uid)
		coi_contact_update_try_merge(update, used_token_contact);

	/* see if we have a newer token that we can send */
	latest_token = latest_contact == NULL ? NULL :
		coi_contact_token_in_find_hash(latest_contact,
			used_token->from_to_normalized_hash);
	if (latest_token == NULL && lcrcpt->temp_token) {
		/* Temporary token was used and there isn't a permanent token
		   yet. Generate a new permanent token. Note that from/to
		   become swapped here. */
		if (lmtp_generate_perm_token(lcrcpt, &latest_token))
			coi_contact_update_add_token_in(update, latest_token);
	}
	if (latest_token != NULL &&
	    strcmp(used_token->token_string, latest_token->token_string) != 0) {
		/* token changed - send back the updated token */
		lcrcpt->reply_token = p_strdup(lcrcpt->rcpt->rcpt->pool,
					       latest_token->token_string);
	}

	if (lcrcpt->my_token != NULL) {
		/* Add/update stored MYSTOKEN if it has changed. */
		latest_token = latest_contact == NULL ? NULL :
			coi_contact_token_out_find_hash(latest_contact,
				coi_contact_generate_hash(lcrcpt->to_normalized, from_normalized));
		if (latest_token == NULL ||
		    strcmp(lcrcpt->my_token->token_string,
			   latest_token->token_string) != 0)
			coi_contact_update_add_token_out(update, lcrcpt->my_token);
	}
	if (coi_contact_list_update(coi_trans, &update, &error_storage) < 0) {
		i_error("Failed to commit COI contact update: %s",
			mail_storage_get_last_internal_error(error_storage, NULL));
		return -1;
	}
	return 0;
}

static int
lmtp_coi_verify_token(struct lmtp_coi_client *lcclient,
		      struct coi_context *coi_ctx,
		      struct lmtp_coi_recipient *lcrcpt)
{
	struct smtp_server_recipient *rcpt = lcrcpt->rcpt->rcpt;
	struct mailbox *contact_box;
	struct coi_contact_list *contact_list;
	struct coi_contact_transaction *coi_trans;
	struct coi_contact *used_token_contact = NULL;
	struct coi_token *used_token;
	struct mail_storage *error_storage;
	int ret;

	if (coi_mailbox_open(coi_ctx, COI_MAILBOX_CONTACTS, 0,
			     &contact_box, &error_storage) < 0) {
		i_error("Failed to open %s mailbox: %s", COI_MAILBOX_CONTACTS,
			mail_storage_get_last_internal_error(error_storage, NULL));
		smtp_server_recipient_reply(
			rcpt, 451, "4.2.0", "Temporary internal error");
		return -1;
	}

	contact_list = coi_contact_list_init_mailbox(contact_box);
	coi_trans = coi_contact_transaction_begin(contact_list);
	/* find the given token and make sure it's not expired */

	if (lcrcpt->temp_token) {
		/* Temporary tokens don't exist in contacts.
		   They're already validated. */
		used_token = lcrcpt->token;
		ret = 1;
	} else {
		ret = coi_contact_list_find_token(coi_trans,
			lcclient->trans_state.from_normalized,
			lcrcpt->to_normalized,
			lcrcpt->token->token_string,
			ioloop_time, &used_token_contact, &used_token,
			&error_storage);
	}
	if (ret < 0) {
		i_error("Failed to find STOKEN: %s",
			mail_storage_get_last_internal_error(error_storage, NULL));
		smtp_server_recipient_reply(
			rcpt, 451, "4.2.0", "Temporary internal error");
	} else if (ret == 0) {
		smtp_server_recipient_reply(
			rcpt, 550, "5.7.30",
			"Invalid STOKEN: Permanent token not found from contacts");
	} else {
		/* The token is valid. See if we can send an updated token or
		   if the provided MYSTOKEN differs from what we have stored. */
		if (lmtp_coi_update_contact(&coi_trans, used_token_contact,
					    used_token, lcrcpt,
					    lcclient->trans_state.from_normalized) < 0) {
			/* Token updates failed, but it's not a fatal error.
			   Don't return an error to the client. */
		}
	}
	if (used_token_contact != NULL)
		mail_free(&used_token_contact->mail);
	coi_contact_list_deinit(&contact_list);
	coi_contact_transaction_commit(&coi_trans);
	mailbox_free(&contact_box);
	return ret <= 0 ? -1 : 0;
}

static void
lmtp_coi_client_data_reply(struct smtp_server_recipient *rcpt,
			   struct lmtp_coi_recipient *lcrcpt)
{
	struct lmtp_recipient *lrcpt = lcrcpt->rcpt;
	struct smtp_server_reply *reply;
	const char *token_prefix;

	reply = smtp_server_recipient_get_reply(rcpt);
	i_assert(reply != NULL);

	if (lrcpt->type != LMTP_RECIPIENT_TYPE_LOCAL) {
		/* non-local delivery */
		return;
	}
	if (!smtp_server_reply_is_success(reply)) {
		/* saving failed - don't change the reply */
		return;
	}

	if (lcrcpt->reply_token == NULL)
		return;

	/* token was updated, return it */
	smtp_server_reply_set_status(reply, 250, "2.1.12");
	token_prefix = t_strdup_printf("<%s> ", lcrcpt->reply_token);
	smtp_server_reply_prepend_text(reply, token_prefix);
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
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct mail_user *user = lldctx->rcpt_user;
	struct coi_context *coi_ctx = coi_get_user_context(user);
	const char *client_error;
	int ret = 0;

	if (lcrcpt != NULL) {
		/* Do final STOKEN verification */
		if (lmtp_coi_verify_token(lcclient, coi_ctx, lcrcpt) < 0)
			ret = -1;
	}

	if (ret == 0)
		ret = coi_mail_is_chat(lldctx->src_mail);

	if (ret == 1) {
		/* This is a chat message */
		ret = lmtp_coi_client_store_chat(lrcpt, trans, lldctx,
						 coi_ctx, &client_error);
		if (ret < 0) {
			smtp_server_recipient_reply(
				rcpt, 451, "4.2.0",
				"Failed to save chat message: %s",
				client_error);
		}
	}
	if (ret < 0)
		return -1;
	if (ret > 0) {
		/* already handled */
		return 0;
	}

	return lcclient->super.local_deliver(client, lrcpt, cmd, trans, lldctx);
}

static void lmtp_coi_client_create(struct client *client)
{
	struct lmtp_coi_client *lcclient;
	struct smtp_capability_extra extra_cap;

	lcclient = p_new(client->pool, struct lmtp_coi_client, 1);
	MODULE_CONTEXT_SET(client, lmtp_coi_client_module, lcclient);
	lcclient->client = client;

	lcclient->super = client->v;
	client->v.destroy = lmtp_coi_client_destroy;
	client->v.trans_free = lmtp_coi_client_trans_free;
	client->v.cmd_mail = lmtp_coi_client_cmd_mail;
	client->v.cmd_rcpt = lmtp_coi_client_cmd_rcpt;
	client->v.local_deliver = lmtp_coi_client_local_deliver;

	coi_secret_settings_init(&lcclient->secret_set, client->pool,
		mail_user_set_plugin_getenv(client->user_set, COI_SETTING_TOKEN_TEMP_SECRETS),
		mail_user_set_plugin_getenv(client->user_set, COI_SETTING_TOKEN_PERM_SECRETS));

	i_zero(&extra_cap);
	extra_cap.name = "STOKEN";
	smtp_server_connection_add_extra_capability(client->conn, &extra_cap);

	smtp_server_connection_register_rcpt_param(client->conn, "STOKEN");
	smtp_server_connection_register_rcpt_param(client->conn, "MYSTOKEN");
}

static void lmtp_coi_client_created(struct client **_client)
{
	struct client *client = *_client;

	lmtp_coi_client_create(client);

	if (next_hook_client_created != NULL)
		next_hook_client_created(_client);
}
#endif

void lmtp_coi_plugin_init(struct module *module)
{
#ifdef BUILD_UNFINISHED
	lmtp_coi_module = module;
	next_hook_client_created =
		lmtp_client_created_hook_set(
			lmtp_coi_client_created);
#endif
	lmtp_coi_message_filter_init(module);
	coi_storage_plugin_init(module);
}

void lmtp_coi_plugin_deinit(void)
{
#ifdef BUILD_UNFINISHED
	lmtp_client_created_hook_set(next_hook_client_created);
#endif
	lmtp_coi_message_filter_deinit();
	coi_storage_plugin_deinit();
}

const char *lmtp_coi_plugin_dependencies[] = { NULL };
const char lmtp_coi_plugin_binary_dependency[] = "lmtp";
