#ifndef COI_COMMON_H
#define COI_COMMON_H

#include "mail-storage.h"

/*
 * Message keywords
 */
#define COI_KEYWORD_CHAT "$Chat"

/*
 * Message headers
 */

#define COI_MSGHDR_CHAT "Chat-Version"
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
#define COI_SETTING_TRUST_MSGID_PREFIX "coi_trust_msgid_prefix"
#define COI_SETTING_TOKEN_TEMP_SECRETS "coi_token_temp_secrets"
#define COI_SETTING_TOKEN_PERM_SECRETS "coi_token_perm_secrets"

#define COI_PERM_TOKEN_VALIDITY_SECS (3600*24*365) /* FIXME: move to setting */

#define MAILBOX_ATTRIBUTE_COI_PREFIX "vendor/vendor.dovecot/coi/"

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
	struct coi_config_cache *config_cache;

	uint32_t list_index_ext_id;
};

struct coi_context *
coi_context_init(struct mail_user *user) ATTR_NULL(2);
void coi_context_deinit(struct coi_context **_coi_ctx);

struct coi_context *coi_get_user_context(struct mail_user *user);

const char *coi_get_mailbox_root(struct coi_context *coi_ctx);
const char *
coi_mailbox_get_name(struct coi_context *coi_ctx, const char *base_name);
const char *coi_normalize_smtp_address(const struct smtp_address *address);

/* Open a COI mailbox. base_name should be one of the COI_MAILBOX_* macros.
   Returns 1 on success, 0 if mailbox doesn't exist, -1 on other errors.
   On errors the storage error is logged. */
int coi_mailbox_open(struct coi_context *coi_ctx, const char *base_name,
		     enum mailbox_flags flags, struct mailbox **box_r,
		     struct mail_storage **storage_r);

/*
 * Chat message recognition
 */

int coi_mail_is_chat(struct mail *mail);

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
