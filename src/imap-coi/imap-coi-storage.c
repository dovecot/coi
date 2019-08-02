/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "coi-common.h"
#include "coi-config.h"
#include "imap-coi-plugin.h"

#define IMAP_COI_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, imap_coi_storage_module)
#define IMAP_COI_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, imap_coi_mail_module)

struct imap_coi_mailbox_transaction {
	union mailbox_transaction_module_context module_ctx;
	ARRAY_TYPE(seq_range) move_uids;
};

static MODULE_CONTEXT_DEFINE_INIT(imap_coi_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(imap_coi_mail_module, &mail_module_register);

static struct mailbox_transaction_context *
imap_coi_mailbox_transaction_begin(struct mailbox *box,
				   enum mailbox_transaction_flags flags,
				   const char *reason)
{
	union mailbox_module_context *icbox = IMAP_COI_STORAGE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct imap_coi_mailbox_transaction *ictrans;

	t = icbox->super.transaction_begin(box, flags, reason);

	ictrans = i_new(struct imap_coi_mailbox_transaction, 1);
	i_array_init(&ictrans->move_uids, 4);
	MODULE_CONTEXT_SET(t, imap_coi_storage_module, ictrans);
	return t;
}

static void
imap_coi_mailbox_transaction_free(struct imap_coi_mailbox_transaction *ictrans)
{
	array_free(&ictrans->move_uids);
	i_free(ictrans);
}

static int
imap_coi_move_mails(struct mailbox *box,
		    struct imap_coi_mailbox_transaction *ictrans)
{
	struct coi_context *coi_ctx = coi_get_user_context(box->storage->user);
	struct mailbox_transaction_context *src_trans, *dest_trans;
	struct mailbox *dest_box;
	struct mail_storage *dest_storage;
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;
	struct mail_search_context *search_ctx;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	struct coi_config config;
	int ret = 0;

	if (array_count(&ictrans->move_uids) == 0)
		return 0;

	/* do the moving only if the current filtering rule is "seen" (we could
	   have checked it earlier also, but it's simpler here..) */
	if (coi_config_read(coi_ctx, &config) < 0)
		return -1;
	if (config.filter != COI_CONFIG_FILTER_SEEN)
		return 0;

	if (coi_mailbox_open(coi_ctx, COI_MAILBOX_CHATS,
			     MAILBOX_FLAG_AUTO_CREATE | MAILBOX_FLAG_SAVEONLY,
			     &dest_box, &dest_storage) <= 0)
		return -1;

	src_trans = mailbox_transaction_begin(box, 0, "COI Chats move");
	dest_trans = mailbox_transaction_begin(dest_box,
				MAILBOX_TRANSACTION_FLAG_EXTERNAL |
				MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS,
				"COI Chats move");

	search_args = mail_search_build_init();
	sarg = mail_search_build_add(search_args, SEARCH_UIDSET);
	sarg->value.seqset = ictrans->move_uids;

	search_ctx = mailbox_search_init(src_trans, search_args, NULL, 0, NULL);
	while (mailbox_search_next(search_ctx, &mail)) {
		if (!mail->expunged) {
			save_ctx = mailbox_save_alloc(dest_trans);
			mailbox_save_copy_flags(save_ctx, mail);
			if (mailbox_move(&save_ctx, mail) < 0)
				ret = -1;
		}
	}
	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	mail_search_args_unref(&search_args);

	if (mailbox_transaction_commit(&src_trans) < 0)
		ret = -1;
	if (mailbox_transaction_commit(&dest_trans) < 0)
		ret = -1;
	mailbox_free(&dest_box);
	return ret;
}

static int
imap_coi_mailbox_transaction_commit(
	struct mailbox_transaction_context *t,
	struct mail_transaction_commit_changes *changes_r)
{
	struct imap_coi_mailbox_transaction *ictrans =
		IMAP_COI_STORAGE_CONTEXT(t);
	struct mailbox *box = t->box;
	union mailbox_module_context *icbox = IMAP_COI_STORAGE_CONTEXT(box);
	int ret = 0;

	if ((icbox->super.transaction_commit(t, changes_r)) < 0)
		ret = -1;
	else {
		/* if it fails, there's not really anything we can do */
		(void)imap_coi_move_mails(box, ictrans);
	}
	imap_coi_mailbox_transaction_free(ictrans);
	return ret;
}

static void
imap_coi_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct imap_coi_mailbox_transaction *ictrans =
		IMAP_COI_STORAGE_CONTEXT(t);
	union mailbox_module_context *icbox = IMAP_COI_STORAGE_CONTEXT(t->box);

	icbox->super.transaction_rollback(t);
	imap_coi_mailbox_transaction_free(ictrans);
}

static void imap_coi_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *icbox;

	icbox = p_new(box->pool, union mailbox_module_context, 1);
	icbox->super = *v;
	box->vlast = &icbox->super;

	v->transaction_begin = imap_coi_mailbox_transaction_begin;
	v->transaction_commit = imap_coi_mailbox_transaction_commit;
	v->transaction_rollback = imap_coi_mailbox_transaction_rollback;
	MODULE_CONTEXT_SET_SELF(box, imap_coi_storage_module, icbox);
}

static void
imap_coi_update_flags(struct mail *mail, enum modify_type modify_type,
		      enum mail_flags flags)
{
	struct mail_private *pmail =
		container_of(mail, struct mail_private, mail);
	union mail_module_context *icmail = IMAP_COI_MAIL_CONTEXT(pmail);
	struct imap_coi_mailbox_transaction *ictrans =
		IMAP_COI_STORAGE_CONTEXT(mail->transaction);

	if (mail->box->inbox_user &&
	    (flags & MAIL_SEEN) != 0 && modify_type != MODIFY_REMOVE &&
	    (mail_get_flags(mail) & MAIL_SEEN) == 0) {
		/* Adding \Seen flag to a mail in INBOX. Does it also have
		   $Chat keyword? */
		const char *const *old_keywords = mail_get_keywords(mail);
		if (str_array_icase_find(old_keywords, COI_KEYWORD_CHAT)) {
			/* Yes, move it to Chats */
			seq_range_array_add(&ictrans->move_uids, mail->uid);
		}
	}
	icmail->super.update_flags(mail, modify_type, flags);
}

static void imap_coi_mail_allocated(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *icmail;

	icmail = p_new(mail->pool, union mail_module_context, 1);
	icmail->super = *v;
	mail->vlast = &icmail->super;

	v->update_flags = imap_coi_update_flags;
	MODULE_CONTEXT_SET_SELF(mail, imap_coi_mail_module, icmail);
}

static struct mail_storage_hooks imap_coi_mail_storage_hooks = {
	.mailbox_allocated = imap_coi_mailbox_allocated,
	.mail_allocated = imap_coi_mail_allocated,
};


void imap_coi_storage_init(struct module *module)
{
	mail_storage_hooks_add(module, &imap_coi_mail_storage_hooks);
}

void imap_coi_storage_deinit(void)
{
	mail_storage_hooks_remove(&imap_coi_mail_storage_hooks);
}
