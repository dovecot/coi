/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "module-context.h"
#include "mail-user.h"
#include "smtp-address.h"
#include "smtp-params.h"
#include "smtp-client-connection.h"
#include "submission-recipient.h"
#include "submission-backend-relay.h"
#include "submission-coi-plugin.h"

#include "coi-common.h"

#define LMTP_SOCKET_NAME "lmtp"

#define SUBMISSION_COI_CONTEXT(obj) \
	MODULE_CONTEXT(obj, submission_coi_client_module)
#define SUBMISSION_COI_BACKEND_CONTEXT(obj) \
	MODULE_CONTEXT(obj, submission_coi_backend_module)
#define SUBMISSION_COI_RCPT_CONTEXT(obj) \
	MODULE_CONTEXT(obj, submission_coi_recipient_module)

struct submisison_coi_recipient;
struct submission_coi_backend;
struct submission_coi_client;

// FIXME: Debugging messages in this plugin need to use events

struct submission_coi_recipient {
	union submission_recipient_module_context module_ctx;
	struct submission_recipient *rcpt;

	struct submission_coi_recipient *next;

	const char *token, *my_token;
};

struct submission_coi_backend {
	union submission_backend_module_context module_ctx;
	struct submission_backend_vfuncs super;
	struct submission_backend *backend;
	struct submission_backend_relay *relay;

	const char *hostname; // FIXME: probably too simplistic

	struct smtp_client_connection *conn;
	struct submission_coi_backend *next;

	struct {
		struct smtp_address *mail_from;
		struct smtp_params_mail mail_params;
	} trans_state;

	bool have_coi:1;
};

struct submission_coi_client {
	union submission_module_context module_ctx;
	struct submission_client_vfuncs super;
	struct client *client;

	struct submission_coi_backend *backends;
	struct submission_coi_backend *lmtp_backend;

	struct coi_context *coi_ctx;

	struct {
		struct submission_coi_recipient *rcpts;

		bool sync_enabled:1;
	} trans_state;

	bool lmtp_backend_have_coi:1;
};

const char *submission_coi_plugin_version = DOVECOT_ABI_VERSION;

static struct module *submission_coi_module;
static MODULE_CONTEXT_DEFINE_INIT(submission_coi_client_module,
				  &submission_module_register);
static MODULE_CONTEXT_DEFINE_INIT(submission_coi_backend_module,
				  &submission_backend_module_register);
static MODULE_CONTEXT_DEFINE_INIT(submission_coi_recipient_module,
				  &submission_recipient_module_register);

static submission_client_created_func_t *next_hook_client_created;

static void
submission_coi_backend_trans_start(struct submission_backend *backend,
				   struct smtp_server_transaction *trans,
				   const struct smtp_address *path,
				   const struct smtp_params_mail *params);
static int
submission_coi_cmd_rcpt_continue(struct submission_coi_client *scclient,
				 struct submission_coi_recipient *scrcpt);

static void
submission_coi_client_destroy(struct client *client, const char *prefix,
			      const char *reason)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);

	coi_context_deinit(&scclient->coi_ctx);

	scclient->super.destroy(client, prefix, reason);
}

static void
submission_coi_client_trans_free(struct client *client,
				 struct smtp_server_transaction *trans)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);

	i_debug("coi: Transaction free");

	i_zero(&scclient->trans_state);

	scclient->super.trans_free(client, trans);
}

static void
submission_coi_backend_ready(struct submission_backend *backend,
			     enum smtp_capability caps)
{
	struct client *client = backend->client;
	struct submission_coi_client *scclient =
		SUBMISSION_COI_CONTEXT(client);
	struct submission_coi_backend *scbackend =
		SUBMISSION_COI_BACKEND_CONTEXT(backend);
	struct submission_coi_recipient *scrcpt;
	struct smtp_client_connection *cl_conn = scbackend->conn;
	struct smtp_server_connection *sv_conn = client->conn;
	struct smtp_server_transaction *sv_trans =
		smtp_server_connection_get_transaction(sv_conn);
	const struct smtp_capability_extra *cap_sync, *cap_coi;

	if (scbackend == scclient->lmtp_backend)
		i_debug("coi: LMTP backend is ready");
	else
		i_debug("coi: SMTP backend %s is ready", scbackend->hostname);

	/* The secondary backend is ready. We can now determine its
	   capabilities */
	cap_sync = smtp_client_connection_get_extra_capability(cl_conn, "SYNC");
	cap_coi = smtp_client_connection_get_extra_capability(cl_conn, "COI");
	scbackend->have_coi = (cap_sync != NULL && cap_coi != NULL);

	if (scbackend->have_coi) {
		i_debug("coi: Backend supports COI");
		/* Enable sync behavior for client transaction */
		(void)submission_backend_relay_init_transaction(
			scbackend->relay,
			SMTP_CLIENT_TRANSACTION_FLAG_REPLY_PER_RCPT);
	} else {
		i_debug("coi: Backend does not support COI");
		// FIXME: which should actually be an error
	}

	scrcpt = scclient->trans_state.rcpts;
	while (scrcpt != NULL) {
		struct submission_recipient *srcpt = scrcpt->rcpt;
		struct smtp_server_recipient *rcpt = srcpt->rcpt;
		struct smtp_server_cmd_ctx *cmd = rcpt->cmd;

		if (srcpt->backend != backend) {
			/* This recipient is not for this particular secondary
			   backend */
			scrcpt = scrcpt->next;
			continue;
		}

		/* Because we returned 0 on cmd_rcpt client vfunc earlier, we
		   are now responsible to submit the default reply when our
		   super returns > 0. */
		if (submission_coi_cmd_rcpt_continue(scclient, scrcpt) > 0 &&
		    !smtp_server_command_is_replied(cmd->cmd))
			smtp_server_cmd_rcpt_reply_success(cmd);

		scrcpt = scrcpt->next;
	}

	if (scbackend->super.ready != NULL)
		scbackend->super.ready(backend, caps);

	if (sv_trans != NULL) {
		submission_coi_backend_trans_start(
			backend, sv_trans,
			scbackend->trans_state.mail_from,
			&scbackend->trans_state.mail_params);
	}
}

static void
submission_coi_backend_trans_start(struct submission_backend *backend,
				   struct smtp_server_transaction *trans,
				   const struct smtp_address *path,
				   const struct smtp_params_mail *params)
{
	struct client *client = backend->client;
	struct submission_coi_backend *scbackend =
		SUBMISSION_COI_BACKEND_CONTEXT(backend);
	struct smtp_params_mail new_params;
	pool_t pool = pool_datastack_create();

	i_debug("coi: Backend transaction start");

	/* Don't start the transaction unless the backend is ready */
	if (!backend->ready) {
		/* The path and parameter values need to be preserved, since
		   another plugin may have modified them.
		 */
		i_assert(scbackend->trans_state.mail_from == NULL);
		smtp_params_mail_copy(client->state.pool,
				      &scbackend->trans_state.mail_params,
				      params);
		scbackend->trans_state.mail_from =
			smtp_address_clone(client->state.pool, path);
		return;
	}

	if (scbackend->have_coi) {
		i_debug("coi: Started backend transaction (with COI)");
		smtp_params_mail_copy(pool, &new_params, params);
		smtp_params_mail_add_extra(&new_params, pool, "SYNC", NULL);
		params = &new_params;
	} else {
		i_debug("coi: Started backend transaction (without COI)");
	}

	scbackend->super.trans_start(backend, trans, path, params);
}

static void
submission_coi_backend_trans_free(struct submission_backend *backend,
				  struct smtp_server_transaction *trans)
{
	struct submission_coi_backend *scbackend =
		SUBMISSION_COI_BACKEND_CONTEXT(backend);

	i_debug("coi: Backend transaction free");
	i_zero(&scbackend->trans_state);

	scbackend->super.trans_free(backend, trans);
}

static struct submission_coi_backend *
submission_coi_backend_create(struct client *client,
			      struct submission_backend_relay *relay)
{
	struct submission_coi_client *scclient =
		SUBMISSION_COI_CONTEXT(client);
	struct submission_coi_backend *scbackend;
	struct submission_backend *backend =
		submission_backend_relay_get(relay);

	scbackend = p_new(backend->pool, struct submission_coi_backend, 1);
	MODULE_CONTEXT_SET(backend, submission_coi_backend_module, scbackend);
	scbackend->backend = backend;
	scbackend->relay = relay;

	scbackend->next = scclient->backends;
	scclient->backends = scbackend;

	scbackend->conn = submission_backend_relay_get_connection(relay);
	smtp_client_connection_accept_extra_capability(scbackend->conn, "SYNC");
	smtp_client_connection_accept_extra_capability(scbackend->conn, "COI");

	scbackend->super = backend->v;
	backend->v.ready = submission_coi_backend_ready;
	backend->v.trans_start = submission_coi_backend_trans_start;
	backend->v.trans_free = submission_coi_backend_trans_free;

	submission_backend_start(backend);

	return scbackend;
}

static struct submission_backend *
submission_coi_lmtp_backend_init(struct client *client)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);
	struct submision_backend_relay_settings relay_set;
	const struct submission_settings *set = client->set;
	struct submission_backend_relay *relay;

	i_debug("coi: Create LMTP backend");

	if (scclient->lmtp_backend != NULL)
		return scclient->lmtp_backend->backend;

	i_zero(&relay_set);
	relay_set.my_hostname = set->hostname;
	relay_set.protocol = SMTP_PROTOCOL_LMTP;
        relay_set.path = t_strconcat(client->user->set->base_dir,
				     "/"LMTP_SOCKET_NAME, NULL);
	relay_set.max_idle_time = set->submission_relay_max_idle_time;
	relay_set.connect_timeout_msecs = set->submission_relay_connect_timeout;
	relay_set.command_timeout_msecs = set->submission_relay_command_timeout;
	relay_set.trusted = TRUE;
	relay = submission_backend_relay_create(client, &relay_set);

	scclient->lmtp_backend =
		submission_coi_backend_create(client, relay);
	return scclient->lmtp_backend->backend;
}

static struct submission_backend *
submission_coi_esmtp_backend_init(struct client *client, const char *hostname)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);
	struct submision_backend_relay_settings relay_set;
	const struct submission_settings *set = client->set;
	struct submission_coi_backend *scbackend;
	struct submission_backend_relay *relay;

	scbackend = scclient->backends;
	while (scbackend != NULL) {
		if (scbackend != scclient->lmtp_backend &&
		    strcasecmp(scbackend->hostname, hostname) == 0) {
			i_debug("coi: Reusing SMTP relay backend");
			return scbackend->backend;
		}
		scbackend = scbackend->next;
	}

	i_debug("coi: Create SMTP relay backend");

	i_zero(&relay_set);
	relay_set.my_hostname = set->hostname;
	relay_set.protocol = SMTP_PROTOCOL_SMTP;
	relay_set.host = hostname;
	relay_set.port = 587; // FIXME
	relay_set.user = "harrie"; // FIXME: some COI-specific token-based authentication
	relay_set.password = "frop";
	relay_set.max_idle_time = set->submission_relay_max_idle_time;
	relay_set.connect_timeout_msecs = set->submission_relay_connect_timeout;
	relay_set.command_timeout_msecs = set->submission_relay_command_timeout;
	relay_set.trusted = FALSE; /* Don't trust remote server */
	relay = submission_backend_relay_create(client, &relay_set);

	scbackend = submission_coi_backend_create(client, relay);
	scbackend->hostname = p_strdup(scbackend->backend->pool, hostname);
	return scbackend->backend;
}

static int
submission_coi_client_cmd_mail(struct client *client,
			       struct smtp_server_cmd_ctx *cmd,
			       struct smtp_server_cmd_mail *data)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);
	const char *sync_param;

	i_debug("coi: MAIL command");

	if (smtp_params_mail_drop_extra(&data->params, "SYNC", &sync_param)) {

		i_debug("coi: MAIL command: SYNC capability is active");

		if (sync_param != NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Unexpected SYNC parameter value");
			return -1;
		}
		scclient->trans_state.sync_enabled = TRUE;
		data->flags |= SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT;
	}

	return scclient->super.cmd_mail(client, cmd, data);
}

static int
submission_coi_cmd_rcpt_continue(struct submission_coi_client *scclient,
				 struct submission_coi_recipient *scrcpt)
{
	struct client *client = scclient->client;
	struct submission_recipient *srcpt = scrcpt->rcpt;
	struct smtp_server_recipient *rcpt = srcpt->rcpt;
	struct smtp_server_cmd_ctx *cmd = rcpt->cmd;
	struct submission_coi_backend *scbackend =
		SUBMISSION_COI_BACKEND_CONTEXT(srcpt->backend);

	i_debug("coi: RCPT command: Continue");

	i_assert(scbackend != NULL);
	if (scbackend->have_coi) {
		i_debug("coi: RCPT command: COI enabled");
		// FIXME: probably some more logic here
		// FIXME: just forwarding the tokens we got before.
		smtp_params_rcpt_add_extra(&rcpt->params, rcpt->pool,
					   "MYTOKEN", scrcpt->my_token);
		smtp_params_rcpt_add_extra(&rcpt->params, rcpt->pool,
					   "TOKEN", scrcpt->token);
	}

	return scclient->super.cmd_rcpt(client, cmd, srcpt);
}

static int
submission_coi_cmd_rcpt_chat(struct submission_coi_client *scclient,
			     struct submission_recipient *srcpt,
			     const char *my_token, const char *token)
{
	struct client *client = scclient->client;
	struct smtp_server_recipient *rcpt = srcpt->rcpt;
	struct submission_coi_recipient *scrcpt;

	i_debug("coi: RCPT command: This is a chat recipient");

	scrcpt = p_new(rcpt->pool, struct submission_coi_recipient, 1);
	MODULE_CONTEXT_SET(srcpt, submission_coi_recipient_module, scrcpt);
	scrcpt->rcpt = srcpt;

	scrcpt->token = p_strdup(rcpt->pool, token);
	scrcpt->my_token = p_strdup(rcpt->pool, my_token);

	if (scclient->trans_state.rcpts == NULL) {
		// FIXME: first chat recipient is always put to LMTP for testing
		//        local chat handling
		srcpt->backend = submission_coi_lmtp_backend_init(client);
	} else {
		// FIXME: subsequent chat recipients are always put to hardcoded
		//        remote submission server
		srcpt->backend = submission_coi_esmtp_backend_init(
			client, "otherhost.example");
	}

	scrcpt->next = scclient->trans_state.rcpts;
	scclient->trans_state.rcpts = scrcpt;

	if (!srcpt->backend->ready) {
		i_debug("coi: RCPT command: "
			"Delay command until backend is ready");
		/* Delay handling of RCPT command until backend is ready */
		return 0;
	}

	return submission_coi_cmd_rcpt_continue(scclient, scrcpt);
}

static int
submission_coi_client_cmd_rcpt(struct client *client,
			       struct smtp_server_cmd_ctx *cmd,
			       struct submission_recipient *srcpt)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);
	struct smtp_server_recipient *rcpt = srcpt->rcpt;
	const char *token, *my_token, *param;

	token = my_token = NULL;
	if (smtp_params_rcpt_drop_extra(&rcpt->params, "TOKEN", &param)) {
		if (param == NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
					  "Missing TOKEN= parameter value");
			return -1;
		}
		if (!scclient->trans_state.sync_enabled) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"The TOKEN= parameter cannot be used without SYNC"); // FIXME: better error
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
		if (!scclient->trans_state.sync_enabled) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"The MYTOKEN= parameter cannot be used without SYNC"); // FIXME: better error
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
		return submission_coi_cmd_rcpt_chat(scclient, srcpt,
						    my_token, token);
	}

	i_debug("coi: RCPT command: This ia a normal recipient");
	return scclient->super.cmd_rcpt(client, cmd, srcpt);
}

static void
submission_coi_client_store_chat(struct submission_coi_client *scclient,
				 struct smtp_server_transaction *trans,
				 struct coi_context *coi_ctx,
				 struct coi_raw_mail *coi_mail)
{
	enum mailbox_transaction_flags trans_flags;
	struct mailbox_transaction_context *mtrans;
	struct mail_save_context *save_ctx;
	struct mailbox *box;
	struct mail_storage *storage;
	const char *header;
	int ret = 0;

	if (scclient->trans_state.rcpts == NULL &&
	    mail_get_first_header(coi_mail->mail, COI_MSGHDR_CHAT,
				  &header) <= 0 &&
	    coi_mail_is_chat_related(coi_ctx, coi_mail->mail) <= 0) {
		/* Not a chat message or it is somehow not possible to
		   determine whether it is one. */
		return;
	}

	if (coi_mailbox_open(coi_ctx, COI_MAILBOX_CHATS,
			     MAILBOX_FLAG_AUTO_CREATE |
			     MAILBOX_FLAG_SAVEONLY | MAILBOX_FLAG_POST_SESSION,
			     &box, &storage) <= 0)
		return;

	trans_flags = MAILBOX_TRANSACTION_FLAG_EXTERNAL;
	mtrans = mailbox_transaction_begin(box, trans_flags, __func__);
	save_ctx = mailbox_save_alloc(mtrans);
	if (trans->mail_from != NULL) {
		mailbox_save_set_from_envelope(save_ctx,
			smtp_address_encode(trans->mail_from));
	}

	if (mailbox_save_using_mail(&save_ctx, coi_mail->mail) < 0)
		ret = -1;

	if (ret < 0)
		mailbox_transaction_rollback(&mtrans);
	else
		ret = mailbox_transaction_commit(&mtrans);

	if (ret < 0) {
		i_info("COI: Failed to save message to chats mailbox `%s': %s",
		       mailbox_get_vname(box),
		       mail_storage_get_last_internal_error(storage, NULL));
	} else {
		i_info("COI: Saved message to chats mailbox `%s'",
		       mailbox_get_vname(box));
	}

	mailbox_free(&box);
}

static int
submission_coi_client_cmd_data(struct client *client,
			       struct smtp_server_cmd_ctx *cmd,
			       struct smtp_server_transaction *trans,
			       struct istream *data_input, uoff_t data_size)
{
	struct submission_coi_client *scclient = SUBMISSION_COI_CONTEXT(client);
	struct coi_raw_mail *coi_mail;

	/* Make sure data input stream is at the beginning (other plugins may
	   have messed with it. */
	i_stream_seek(data_input, 0);

	if (coi_raw_mail_open(scclient->coi_ctx, trans->mail_from,
			      data_input, &coi_mail) == 0) {
		submission_coi_client_store_chat(scclient, trans,
						 scclient->coi_ctx, coi_mail);
		coi_raw_mail_close(&coi_mail);
	}

	return scclient->super.cmd_data(client, cmd, trans,
					data_input, data_size);
}

static void submission_coi_client_create(struct client *client)
{
	struct submission_coi_client *scclient;
	struct submission_backend_relay *backend;
	struct smtp_client_connection *smtp_conn;

	i_debug("coi: Client create");

	scclient = p_new(client->pool, struct submission_coi_client, 1);
	MODULE_CONTEXT_SET(client, submission_coi_client_module, scclient);
	scclient->client = client;

	scclient->super = client->v;
	client->v.destroy = submission_coi_client_destroy;
	client->v.trans_free = submission_coi_client_trans_free;
	client->v.cmd_mail = submission_coi_client_cmd_mail;
	client->v.cmd_rcpt = submission_coi_client_cmd_rcpt;
	client->v.cmd_data = submission_coi_client_cmd_data;

	scclient->coi_ctx = coi_context_init(client->user);

	client_add_extra_capability(client, "SYNC", NULL); // FIXME: better name for this capability
	client_add_extra_capability(client, "COI", NULL); // FIXME: better name for this protocol

	smtp_server_connection_register_mail_param(client->conn, "SYNC"); // FIXME: better name for this parameter
	smtp_server_connection_register_rcpt_param(client->conn, "TOKEN");
	smtp_server_connection_register_rcpt_param(client->conn, "MYTOKEN");

	backend = client->backend_default_relay;
	if (backend != NULL) {
		smtp_conn = submission_backend_relay_get_connection(backend);
		smtp_client_connection_accept_extra_capability(smtp_conn, "SYNC");
		smtp_client_connection_accept_extra_capability(smtp_conn, "COI");
	}
}

static void submission_coi_client_created(struct client **_client)
{
	struct client *client = *_client;

	if (mail_user_is_plugin_loaded(client->user, submission_coi_module))
		submission_coi_client_create(client);

	if (next_hook_client_created != NULL)
		next_hook_client_created(_client);
}

void submission_coi_plugin_init(struct module *module)
{
	submission_coi_module = module;
	next_hook_client_created =
		submission_client_created_hook_set(
			submission_coi_client_created);
}

void submission_coi_plugin_deinit(void)
{
	submission_client_created_hook_set(next_hook_client_created);
}

const char *submission_coi_plugin_dependencies[] = { NULL };
const char submission_coi_plugin_binary_dependency[] = "submission";
