/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-storage.h"
#include "raw-storage.h"
#include "smtp-address.h"

#include "coi-common.h"

/*
 * COI context
 */

struct coi_context {
	pool_t pool;

	struct mail_user *user;
	struct mail_user *raw_mail_user;

	const char *root_box_name;
	struct mail_namespace *root_ns;

	const char *chats_box_name;
};

struct coi_context *
coi_context_init(struct mail_user *user)
{
	struct coi_context *coi_ctx;
	struct mail_namespace *ns;
	void **sets;
	pool_t pool;
	const char *root_box_name;

	pool = pool_alloconly_create("coi context", 2048);
	coi_ctx = p_new(pool, struct coi_context, 1);
	coi_ctx->pool = pool;
	coi_ctx->user = user;

	root_box_name = mail_user_plugin_getenv(user, COI_SETTING_MAILBOX_ROOT);
	if (root_box_name == NULL) {
		ns = mail_namespace_find_inbox(user->namespaces);

		root_box_name = t_strconcat(ns->prefix,
					    COI_MAILBOX_DEFAULT_ROOT, NULL);
	} else {
		ns = mail_namespace_find(user->namespaces, root_box_name);
	}
	coi_ctx->root_box_name = p_strdup(pool, root_box_name);
	coi_ctx->root_ns = ns;

	sets = master_service_settings_get_others(master_service);
	coi_ctx->raw_mail_user =
		raw_storage_create_from_set(user->set_info, sets[0]);

	return coi_ctx;
}

void coi_context_deinit(struct coi_context **_coi_ctx)
{
	struct coi_context *coi_ctx = *_coi_ctx;

	*_coi_ctx = NULL;

	if (coi_ctx == NULL)
		return;

	mail_user_unref(&coi_ctx->raw_mail_user);
	pool_unref(&coi_ctx->pool);
}

const char *coi_get_mailbox_root(struct coi_context *coi_ctx)
{
	return coi_ctx->root_box_name;
}

/*
 * Chats mailbox
 */

static const char *
coi_mailbox_chats_get_name(struct coi_context *coi_ctx)
{
	string_t *name;

	if (coi_ctx->chats_box_name != NULL)
		return coi_ctx->chats_box_name;

	name = t_str_new(256);
	str_append(name, coi_ctx->root_box_name);
	str_append_c(name, mail_namespace_get_sep(coi_ctx->root_ns));
	str_append(name, COI_MAILBOX_CHATS);

	coi_ctx->chats_box_name = p_strdup(coi_ctx->pool, str_c(name));
	return coi_ctx->chats_box_name;
}

int coi_mailbox_chats_open(struct coi_context *coi_ctx,
			   enum mailbox_flags flags, struct mailbox **box_r,
			   struct mail_storage **storage_r)
{
	struct mailbox *box;

	*box_r = NULL;

	flags |= MAILBOX_FLAG_AUTO_CREATE;
	box = *box_r = mailbox_alloc(coi_ctx->root_ns->list,
				     coi_mailbox_chats_get_name(coi_ctx),
				     flags);
	*storage_r = mailbox_get_storage(box);
	if (mailbox_open(box) == 0)
		return 0;

	i_info("COI: Failed to open chats mailbox `%s': %s",
	       mailbox_get_vname(box),
	       mail_storage_get_last_internal_error(*storage_r, NULL));
	mailbox_free(box_r);
	return -1;
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
