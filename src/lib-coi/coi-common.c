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

/* All COI chat messages have Message-ID with this prefix */
#define COI_CHAT_MSGID_PREFIX "coi$"

/*
 * COI context
 */

struct coi_context {
	pool_t pool;

	struct mail_user *user;
	struct mail_user *raw_mail_user;

	const char *root_box_name;
	struct mail_namespace *root_ns;

	bool coi_trust_msgid_prefix;
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

	coi_ctx->coi_trust_msgid_prefix =
		mail_user_plugin_getenv_bool(user, COI_SETTING_TRUST_MSGID_PREFIX);

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
coi_mailbox_get_name(struct coi_context *coi_ctx, const char *base_name)
{
	string_t *name;

	name = t_str_new(256);
	str_append(name, coi_ctx->root_box_name);
	str_append_c(name, mail_namespace_get_sep(coi_ctx->root_ns));
	str_append(name, base_name);
	return str_c(name);
}

static int coi_mailbox_open(struct coi_context *coi_ctx, const char *base_name,
			    enum mailbox_flags flags, struct mailbox **box_r,
			    struct mail_storage **storage_r)
{
	struct mailbox *box;

	*box_r = NULL;

	flags |= MAILBOX_FLAG_AUTO_CREATE;
	box = *box_r = mailbox_alloc(coi_ctx->root_ns->list,
		coi_mailbox_get_name(coi_ctx, base_name), flags);
	*storage_r = mailbox_get_storage(box);
	if (mailbox_open(box) == 0)
		return 0;

	i_info("COI: Failed to open mailbox `%s': %s",
	       mailbox_get_vname(box),
	       mail_storage_get_last_internal_error(*storage_r, NULL));
	mailbox_free(box_r);
	return -1;
}

int coi_mailbox_chats_open(struct coi_context *coi_ctx,
			   enum mailbox_flags flags, struct mailbox **box_r,
			   struct mail_storage **storage_r)
{
	return coi_mailbox_open(coi_ctx, COI_MAILBOX_CHATS,
				flags, box_r, storage_r);
}

/*
 * Chat message recognition
 */

static int
coi_mailbox_chats_has_reference(struct coi_context *coi_ctx,
				const char *const *msgids)
{
	struct mail_storage *storage;
	struct mailbox *box;
	struct mailbox_transaction_context *mtrans;
	struct mail_search_args *search_args;
	struct mail_search_arg *or_arg, **subargs;
	const char *const *msgidp;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	int ret = 0;

	if (*msgids == NULL)
		return 0;
	if (coi_ctx->coi_trust_msgid_prefix)
		return 1;

	if (coi_mailbox_chats_open(coi_ctx, 0, &box, &storage) < 0) {
		// FIXME: error?
		return -1;
	}

	mtrans = mailbox_transaction_begin(box, 0, __func__);

	/* Compose search for all message IDs of interest */
	search_args = mail_search_build_init();
	msgidp = msgids;
	if (msgidp[1] == NULL)
		subargs = &search_args->args;
	else {
		or_arg = mail_search_build_add(search_args, SEARCH_OR);
		subargs = &or_arg->value.subargs;
	}
	while (*msgidp != NULL) {
		struct mail_search_arg *sarg;

		sarg = p_new(search_args->pool, struct mail_search_arg, 1);
		sarg->type = SEARCH_HEADER;

		sarg->next = *subargs;
		*subargs = sarg;

		sarg->hdr_field_name = p_strdup(search_args->pool,
						"Message-ID");
		sarg->value.str = p_strdup(search_args->pool, *msgidp);

		msgidp++;
	}

	mail_search_args_init(search_args, box, FALSE, NULL);
	search_ctx = mailbox_search_init(mtrans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		if (!mail->expunged) {
			ret = 1;
			break;
		}
	}

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	mailbox_transaction_rollback(&mtrans);
	mailbox_free(&box);
	return ret;
}

static void
coi_mail_header_read_msgids(const char *value, ARRAY_TYPE(const_string) *msgids)
{
	const char *id;

	while ((id = message_id_get_next(&value)) != NULL) {
		const char *const *idp;
		bool exists = FALSE;

		if (!str_begins(id, COI_CHAT_MSGID_PREFIX))
			continue;

		/* Avoid duplicates */
		array_foreach(msgids, idp) {
			if (strcmp(*idp, id) == 0) {
				exists = TRUE;
				break;
			}
		}
		if (exists)
			continue;

		id = t_strdup(id);
		array_append(msgids, &id, 1);
	}
}

int coi_mail_is_chat_related(struct coi_context *coi_ctx, struct mail *mail)
{
	ARRAY_TYPE(const_string) msgids;
	const char *header = NULL;

	t_array_init(&msgids, 64);

	/* In-Reply-To: */
	if (mail_get_first_header(mail, "in-reply-to", &header) < 0 &&
	    !mail->expunged)
		return -1;
	coi_mail_header_read_msgids(header, &msgids);

	/* References: */
	if (mail_get_first_header(mail, "references", &header) < 0 &&
	    !mail->expunged)
		return -1;
	coi_mail_header_read_msgids(header, &msgids);

	array_append_zero(&msgids);
	return coi_mailbox_chats_has_reference(coi_ctx, array_idx(&msgids, 0));
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
