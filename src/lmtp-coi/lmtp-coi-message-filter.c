/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-address.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "coi-config.h"
#include "coi-common.h"
#include "lmtp-coi-plugin.h"

#define LMTP_COI_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lmtp_coi_storage_module)
#define LMTP_COI_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lmtp_coi_mail_module)

struct lmtp_coi_mail {
	union mail_module_context module_ctx;
	bool add_has_chat_flag;
};

static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lmtp_coi_mail_module, &mail_module_register);

int lmtp_coi_message_filter_save_chat(struct coi_context *coi_ctx,
				      struct mail *src_mail,
				      const struct smtp_address *mail_from,
				      const char **client_error_r)
{
	struct mail_private *pmail =
		container_of(src_mail, struct mail_private, mail);
	struct lmtp_coi_mail *lcmail = LMTP_COI_MAIL_CONTEXT(pmail);
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
	if (!config.enabled)
		return 0;

	if (lcmail == NULL) {
		lcmail = p_new(pmail->pool, struct lmtp_coi_mail, 1);
		MODULE_CONTEXT_SET(pmail, lmtp_coi_mail_module, lcmail);
	}

	/* Add $Chat keyword to all chat mails. This way:
	   1) With filter=none clients can easily differentiate mails in INBOX
	   whether they are chats or not.
	   2) With filter=seen the server can move mails to Chats mailbox
	   3) Push-notifications can see whether the mail is a chat or not. */
	lcmail->add_has_chat_flag = TRUE;

	switch (config.filter) {
	case COI_CONFIG_FILTER_NONE:
		/* store to INBOX */
		return 0;
	case COI_CONFIG_FILTER_ACTIVE:
		break;
	case COI_CONFIG_FILTER_SEEN:
		/* For now store to INBOX, but move to Chats when \Seen flag
		   is set. */
		return 0;
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
	if (mail_from != NULL) {
		mailbox_save_set_from_envelope(save_ctx,
			smtp_address_encode(mail_from));
	}

	if (mailbox_save_using_mail(&save_ctx, src_mail) < 0)
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
	}

	mailbox_free(&box);
	return ret < 0 ? -1 : 1;
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
		const char *const chat_kw_arr[] = { COI_KEYWORD_CHAT, NULL };
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

void lmtp_coi_message_filter_init(struct module *module)
{
	mail_storage_hooks_add(module, &lmtp_coi_mail_storage_hooks);
}

void lmtp_coi_message_filter_deinit(void)
{
	mail_storage_hooks_remove(&lmtp_coi_mail_storage_hooks);
}
