/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "coi-common.h"
#include "coi-config.h"

#define MAX_EXPUNGE_RETRIES 10

static int coi_config_storage_error(struct mailbox *box)
{
	return mailbox_get_last_mail_error(box) == MAIL_ERROR_EXPUNGED ? -1 : 0;
}

static int coi_config_try_read(struct mailbox *box, struct coi_config *config_r)
{
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	struct mailbox_status status;
	const char *value;
	int ret = 1;

	if (mailbox_sync(box, 0) < 0)
		return -1;
	mailbox_get_open_status(box, STATUS_MESSAGES, &status);
	if (status.messages == 0) {
		/* config message is missing - use defaults */
		return 0;
	}

	trans = mailbox_transaction_begin(box, 0, "COI Configuration read");
	/* read configuration from the newest mail */
	mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, status.messages);

	if (mail_get_first_header(mail, "COI-Message-Filter", &value) < 0)
		ret = coi_config_storage_error(box);
	else if (strcmp(value, "active") == 0)
		config_r->filter = COI_CONFIG_FILTER_ACTIVE;
	else if (strcmp(value, "read") == 0)
		config_r->filter = COI_CONFIG_FILTER_READ;
	else
		config_r->filter = COI_CONFIG_FILTER_NONE;

	mail_free(&mail);
	(void)mailbox_transaction_commit(&trans);
	return ret;
}

int coi_config_read(struct coi_context *coi_ctx, struct coi_config *config_r)
{
	struct mailbox *box;
	struct mail_storage *storage;
	int ret;

	ret = coi_mailbox_open(coi_ctx, COI_MAILBOX_CONFIGURATION, 0,
			       &box, &storage);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		/* no configuration mailbox - use defaults */
		i_zero(config_r);
		return 0;
	}

	for (int i = 0, ret = 0; i < MAX_EXPUNGE_RETRIES && ret == 0; i++) {
		i_zero(config_r);
		ret = coi_config_try_read(box, config_r);
	}
	if (ret <= 0) {
		e_error(coi_ctx->user->event,
			"Failed to read COI configuration: %s",
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		ret = 0;
	}
	mailbox_free(&box);
	return ret;
}
