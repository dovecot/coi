#ifndef COI_CONFIG_H
#define COI_CONFIG_H

#include "imap-metadata.h"

#define MAILBOX_ATTRIBUTE_COI_CONFIG_PREFIX \
	MAILBOX_ATTRIBUTE_COI_PREFIX"config/"

#define MAILBOX_ATTRIBUTE_COI_CONFIG_ENABLED \
	MAILBOX_ATTRIBUTE_COI_CONFIG_PREFIX"enabled"
#define MAILBOX_ATTRIBUTE_COI_CONFIG_MAILBOX_ROOT \
	MAILBOX_ATTRIBUTE_COI_CONFIG_PREFIX"mailbox-root"
#define MAILBOX_ATTRIBUTE_COI_CONFIG_MESSAGE_FILTER \
	MAILBOX_ATTRIBUTE_COI_CONFIG_PREFIX"message-filter"

struct coi_context;

enum coi_config_filter {
	/* No filtering */
	COI_CONFIG_FILTER_NONE,
	/* Move chat mails to Chats folder */
	COI_CONFIG_FILTER_ACTIVE,
	/* Move chat mails to Chats folder when \Seen flag is set */
	COI_CONFIG_FILTER_SEEN,
};

struct coi_config {
	bool enabled;
	enum coi_config_filter filter;
};

bool coi_config_filter_parse(const char *str, enum coi_config_filter *filter_r);

int coi_config_read(struct coi_context *coi_ctx, struct coi_config *config_r);
/* Set COI enabled/disabled by changing the
   MAILBOX_ATTRIBUTE_COI_CONFIG_ENABLED. */
int coi_config_set_enabled(struct mail_user *user, bool set);

void coi_config_global_init(void);

#endif
