#ifndef COI_COMMON_H
#define COI_COMMON_H

#include "mail-storage.h"

/*
 * Message headers
 */

#define COI_MSGHDR_CHAT "X-COI-Chat"
#define COI_MSGHDR_TEMP_TOKEN "X-COI-Temporary-Token"

/*
 * Mailboxes
 */

#define COI_MAILBOX_DEFAULT_ROOT "COI"

#define COI_MAILBOX_CHATS "Chats"
#define COI_MAILBOX_CONTACTS "Contacts"

/*
 * Plugin settings
 */

#define COI_SETTING_MAILBOX_ROOT "coi_mailbox_root"

/*
 * COI context
 */

struct coi_context;

struct coi_context *
coi_context_init(struct mail_user *user) ATTR_NULL(2);
void coi_context_deinit(struct coi_context **_coi_ctx);

const char *coi_get_mailbox_root(struct coi_context *coi_ctx);

/*
 * Chats mailbox
 */

int coi_mailbox_chats_open(struct coi_context *coi_ctx,
			   enum mailbox_flags flags, struct mailbox **box_r,
			   struct mail_storage **storage_r);

/*
 * Raw mail
 */

struct coi_raw_mail {
	struct mail *mail;

	struct mailbox *box;
	struct mailbox_transaction_context *trans;
};

int coi_raw_mail_open(struct coi_context *coi_ctx,
		      const struct smtp_address *mail_from,
		      struct istream *msg_input,
		      struct coi_raw_mail **coi_mail_r);
void coi_raw_mail_close(struct coi_raw_mail **_coi_mail);

#endif
