#ifndef COI_CONFIG_H
#define COI_CONFIG_H

struct coi_context;

enum coi_config_filter {
	/* No filtering */
	COI_CONFIG_FILTER_NONE,
	/* Move chat mails to Chats folder */
	COI_CONFIG_FILTER_ACTIVE,
	/* Move chat mails to Chats folder when \Seen flag is set */
	COI_CONFIG_FILTER_READ,
};

struct coi_config {
	enum coi_config_filter filter;
};

int coi_config_read(struct coi_context *coi_ctx, struct coi_config *config_r);

#endif
