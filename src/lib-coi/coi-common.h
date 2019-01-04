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
 * COI context
 */

struct coi_context;

struct coi_context *
coi_context_init(struct mail_user *user) ATTR_NULL(2);
void coi_context_deinit(struct coi_context **_coi_ctx);

#endif
