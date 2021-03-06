/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "message-id.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "raw-storage.h"
#include "smtp-address.h"

#include "coi-common.h"
#include "coi-config.h"

/* All COI chat messages have Message-ID with this prefix */
#define COI_CHAT_MSGID_PREFIX "chat$"
/* All COI chat group messages have Message-ID with this prefix */
#define COI_CHAT_GROUP_MSGID_PREFIX COI_CHAT_MSGID_PREFIX"group."

/*
 * COI context
 */

static void coi_context_parse_settings(struct coi_context *coi_ctx)
{
	struct mail_user *user = coi_ctx->user;
	const char *root_box_name;
	struct mail_namespace *ns;

	/* COI root folder */
	root_box_name = mail_user_plugin_getenv(user, COI_SETTING_MAILBOX_ROOT);
	if (root_box_name == NULL) {
		ns = mail_namespace_find_inbox(user->namespaces);

		root_box_name = t_strconcat(ns->prefix,
					    COI_MAILBOX_DEFAULT_ROOT, NULL);
	} else {
		ns = mail_namespace_find(user->namespaces, root_box_name);
	}
	coi_ctx->root_box_name = p_strdup(coi_ctx->pool, root_box_name);
	coi_ctx->root_ns = ns;
}

struct coi_context *
coi_context_init(struct mail_user *user)
{
	struct coi_context *coi_ctx;
	pool_t pool;

	coi_config_global_init();

	pool = pool_alloconly_create("coi context", 2048);
	coi_ctx = p_new(pool, struct coi_context, 1);
	coi_ctx->pool = pool;
	coi_ctx->user = user;
	coi_context_parse_settings(coi_ctx);

	return coi_ctx;
}

static void coi_context_get_raw_mail_user(struct coi_context *coi_ctx)
{
	void **sets;

	if (coi_ctx->raw_mail_user != NULL)
		return;

	sets = master_service_settings_get_others(master_service);
	coi_ctx->raw_mail_user =
		raw_storage_create_from_set(coi_ctx->user->set_info, sets[0]);
}

void coi_context_deinit(struct coi_context **_coi_ctx)
{
	struct coi_context *coi_ctx = *_coi_ctx;

	*_coi_ctx = NULL;

	if (coi_ctx == NULL)
		return;

	if (coi_ctx->raw_mail_user != NULL)
		mail_user_unref(&coi_ctx->raw_mail_user);
	pool_unref(&coi_ctx->pool);
}

const char *coi_get_mailbox_root(struct coi_context *coi_ctx)
{
	return coi_ctx->root_box_name;
}

const char *coi_normalize_smtp_address(const struct smtp_address *address)
{
	struct smtp_address new_address;

	if (address == NULL) {
		/* address is <> */
		return "";
	}

	i_zero(&new_address);
	new_address.localpart = t_str_lcase(address->localpart);
	new_address.domain = t_str_lcase(address->domain);

	return smtp_address_encode(&new_address);
}

const char *
coi_mailbox_get_name(struct coi_context *coi_ctx, const char *base_name)
{
	string_t *name;

	name = t_str_new(256);
	str_append(name, coi_ctx->root_box_name);
	str_append_c(name, mail_namespace_get_sep(coi_ctx->root_ns));
	str_append(name, base_name);
	return str_c(name);
}

int coi_mailbox_open(struct coi_context *coi_ctx, const char *base_name,
		     enum mailbox_flags flags, struct mailbox **box_r,
		     struct mail_storage **storage_r)
{
	struct mailbox *box;
	const char *errstr;
	enum mail_error error;
	int ret;

	*box_r = NULL;

	box = *box_r = mailbox_alloc(coi_ctx->root_ns->list,
		coi_mailbox_get_name(coi_ctx, base_name), flags);
	*storage_r = mailbox_get_storage(box);
	if (mailbox_open(box) == 0)
		return 1;

	errstr = mailbox_get_last_internal_error(box, &error);
	if (error == MAIL_ERROR_NOTFOUND &&
	    (flags & MAILBOX_FLAG_AUTO_CREATE) == 0)
		ret = 0;
	else {
		i_error("COI: Failed to open mailbox `%s': %s",
			mailbox_get_vname(box), errstr);
		ret = -1;
	}
	mailbox_free(box_r);
	return ret;
}

/*
 * Chat message recognition
 */

static bool coi_msgid_header_has_chat(const char *value)
{
	const char *id;

	if ((id = message_id_get_next(&value)) == NULL)
		return FALSE;
	return str_begins(id, COI_CHAT_MSGID_PREFIX);
}

int coi_mail_is_chat(struct mail *mail)
{
	const char *header = NULL;
	int ret;

	/* Chat-Version: */
	ret = mail_get_first_header(mail, COI_MSGHDR_CHAT, &header);
	if (ret < 0 && !mail->expunged)
		return -1;
	if (ret > 0)
		return 1;

	/* References: In messages generated by the COI client, there's only
	   two msg-ids: <thread root> <parent>. If legacy clients add replies,
	   more msg-ids are appended. However, in any case we only need to
	   check the thread root's msg-id. If there are enough legacy replies,
	   the first chat$ msg-ids will be truncated and the thread becomes
	   converted into an email thread. */
	ret = mail_get_first_header(mail, "references", &header);
	if (ret < 0 && !mail->expunged)
		return -1;
	if (ret > 0 && coi_msgid_header_has_chat(header))
		return 1;

	/* Message-Id: Just in case Chat-Version is dropped by MTAs */
	ret = mail_get_first_header(mail, "message-id", &header);
	if (ret < 0 && !mail->expunged)
		return -1;
	if (ret > 0 && coi_msgid_header_has_chat(header))
		return 1;
	return 0;
}

static bool
coi_msgid_header_get_group(const char *value, const char **group_id_r)
{
	const char *id;

	if ((id = message_id_get_next(&value)) == NULL)
		return FALSE;
	if (!str_begins(id, COI_CHAT_GROUP_MSGID_PREFIX))
		return FALSE;
	*group_id_r = t_strcut(id + strlen(COI_CHAT_GROUP_MSGID_PREFIX), '.');
	return TRUE;
}

int coi_mail_parse_group(struct mail *mail, const char **group_id_r)
{
	const char *header;
	int ret;

	ret = mail_get_first_header(mail, "message-id", &header);
	if (ret < 0 && !mail->expunged)
		return -1;
	if (ret > 0 && coi_msgid_header_get_group(header, group_id_r))
		return 1;

	/* try also References in case this is a reply from legacy client */
	ret = mail_get_first_header(mail, "references", &header);
	if (ret < 0 && !mail->expunged)
		return -1;
	if (ret > 0 && coi_msgid_header_get_group(header, group_id_r))
		return 1;
	return 0;
}

/*
 * COI raw mail
 */

int coi_raw_mail_open(struct coi_context *coi_ctx,
		      const struct smtp_address *mail_from,
		      struct istream *msg_input,
		      struct coi_raw_mail **coi_mail_r)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Return-Path", "References",
		COI_MSGHDR_CHAT, COI_MSGHDR_TEMP_TOKEN, NULL
	};
	struct coi_raw_mail *coi_mail;
	struct mailbox *box;
	struct mailbox_header_lookup_ctx *headers_ctx;
	enum mail_error error;

	*coi_mail_r = NULL;

	coi_context_get_raw_mail_user(coi_ctx);
	if (raw_mailbox_alloc_stream(coi_ctx->raw_mail_user, msg_input,
				     (time_t)-1, smtp_address_encode(mail_from),
				     &box) < 0) {
		i_error("coi: Can't open mail as raw: %s",
			mailbox_get_last_internal_error(box, &error));
		mailbox_free(&box);
		return -1;
	}

	coi_mail = *coi_mail_r = i_new(struct coi_raw_mail, 1);
	coi_mail->box = box;
	coi_mail->trans = mailbox_transaction_begin(box, 0, __func__);

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	coi_mail->mail = mail_alloc(coi_mail->trans, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(coi_mail->mail, 1);
	return 0;
}

void coi_raw_mail_close(struct coi_raw_mail **_coi_mail)
{
	struct coi_raw_mail *coi_mail = *_coi_mail;

	*_coi_mail = NULL;

	mail_free(&coi_mail->mail);
	mailbox_transaction_rollback(&coi_mail->trans);
	mailbox_free(&coi_mail->box);

	i_free(coi_mail);
}
