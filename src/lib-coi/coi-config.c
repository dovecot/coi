/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "coi-common.h"
#include "coi-config.h"

#include "mail-storage-private.h"
#include "mailbox-list-index.h"

#define MAX_EXPUNGE_RETRIES 10

struct coi_config_binary {
	/* UIDVALIDITY and UIDNEXT of the Configuration mailbox at the time
	   this header was written. This is used to verify whether this header
	   is up-to-date. */
	uint32_t uid_validity;
	uint32_t uid_next;

	uint8_t filter; /* enum coi_config_filter */
	uint8_t padding[3];
};

static int coi_config_try_read(struct mailbox *box,
			       uint32_t *uid_validity_r, uint32_t *uid_next_r,
			       struct coi_config *config_r)
{
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	struct mailbox_status status;
	const char *value;
	int ret = 1;

	if (mailbox_sync(box, 0) < 0)
		return -1;
	mailbox_get_open_status(box,
		STATUS_UIDVALIDITY | STATUS_UIDNEXT | STATUS_MESSAGES, &status);
	*uid_validity_r = status.uidvalidity;
	*uid_next_r = status.uidnext;
	if (status.messages == 0) {
		/* config message is missing - use defaults */
		return 0;
	}

	trans = mailbox_transaction_begin(box, 0, "COI Configuration read");
	/* read configuration from the newest mail */
	mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, status.messages);

	if (mail_get_first_header(mail, "COI-Message-Filter", &value) < 0)
		ret = -1;
	else if (strcmp(value, "active") == 0)
		config_r->filter = COI_CONFIG_FILTER_ACTIVE;
	else if (strcmp(value, "seen") == 0)
		config_r->filter = COI_CONFIG_FILTER_SEEN;
	else
		config_r->filter = COI_CONFIG_FILTER_NONE;

	mail_free(&mail);
	(void)mailbox_transaction_commit(&trans);
	return ret;
}

static bool
coi_config_parse_binary(const void *data, size_t size,
			uint32_t expected_uid_validity,
			uint32_t expected_uid_next,
			struct coi_config *config_r)
{
	struct coi_config_binary bin;

	if (size < sizeof(bin))
		return FALSE;
	memcpy(&bin, data, sizeof(bin));

	if (bin.uid_validity != expected_uid_validity ||
	    bin.uid_next != expected_uid_next)
		return FALSE;

	if (bin.filter > COI_CONFIG_FILTER_SEEN)
		return FALSE;
	config_r->filter = bin.filter;
	return TRUE;
}

static void
coi_config_to_binary(const struct coi_config *config,
		     struct coi_config_binary *bin_r)
{
	i_zero(bin_r);
	bin_r->filter = config->filter;
}

static bool
coi_config_try_read_from_list_index(struct coi_context *coi_ctx,
				    struct mailbox *box,
				    struct coi_config *config_r)
{
	struct mail_index_view *list_view;
	struct mailbox_status status;
	uint32_t list_seq;
	const void *data;
	size_t size;
	bool parsed = FALSE;

	i_zero(config_r);

	if (mailbox_list_index_view_open(box, TRUE, &list_view, &list_seq) <= 0)
		return FALSE;

	/* The COI configuration is stored in the mailbox list index header.
	   The list_seq is used only internally by mailbox list index code to
	   see if it needs refreshing. We have an additional check to make sure
	   that the list index's uidvalidity & uidnext match the configuration
	   header in case the list index was refreshed without COI plugin
	   enabled. */
	mail_index_get_header_ext(list_view, coi_ctx->list_index_ext_id,
				  &data, &size);
	if (size > 0 &&
	    mailbox_list_index_status(box->list, list_view, list_seq,
				      STATUS_UIDVALIDITY | STATUS_UIDNEXT,
				      &status, NULL, NULL)) {
		parsed = coi_config_parse_binary(data, size,
						 status.uidvalidity,
						 status.uidnext, config_r);
	}

	mail_index_view_close(&list_view);
	return parsed;
}

static void
coi_config_write_list_index(struct coi_context *coi_ctx, struct mailbox *box,
			    uint32_t uid_validity, uint32_t uid_next,
			    const struct coi_config *config)
{
	struct mail_index *list_index;
	struct mail_index_view *list_view;
	struct mail_index_transaction *list_trans;
	struct coi_config_binary bin;

	/* Update the header without locking the list index. It's just a lot of
	   extra effort and the configuration is unlikely to be changed
	   rapidly. In any case, if there is a race condition and another
	   process updates a newer header, it'll be noticed by the next read. */

	if (!mailbox_list_index_get_index(box->list, &list_index))
		return;

	coi_config_to_binary(config, &bin);
	bin.uid_validity = uid_validity;
	bin.uid_next = uid_next;

	list_view = mail_index_view_open(list_index);
	list_trans = mail_index_transaction_begin(list_view,
		MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header_ext(list_trans, coi_ctx->list_index_ext_id,
				     0, &bin, sizeof(bin));
	(void)mail_index_transaction_commit(&list_trans);
	mail_index_view_close(&list_view);
}

int coi_config_read(struct coi_context *coi_ctx, struct coi_config *config_r)
{
	struct mailbox *box;
	uint32_t uid_validity, uid_next;
	int ret;

	box = mailbox_alloc(coi_ctx->root_ns->list,
		coi_mailbox_get_name(coi_ctx, COI_MAILBOX_CONFIGURATION), 0);
	if (coi_config_try_read_from_list_index(coi_ctx, box, config_r)) {
		mailbox_free(&box);
		return 1;
	}

	if (mailbox_open(box) < 0) {
		enum mail_error error;
		const char *errstr;

		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_NOTFOUND) {
			e_error(box->event,
				"COI: Failed to open mailbox: %s", errstr);
			ret = -1;
		} else {
			/* no configuration mailbox - use defaults */
			i_zero(config_r);
			ret = 0;
		}
		mailbox_free(&box);
		return ret;
	}

	for (int i = 0; i < MAX_EXPUNGE_RETRIES; i++) {
		i_zero(config_r);
		ret = coi_config_try_read(box, &uid_validity,
					  &uid_next, config_r);
		if (ret >= 0 ||
		    mailbox_get_last_mail_error(box) != MAIL_ERROR_EXPUNGED)
			break;
		/* configuration mail was just expunged - retry */
	}
	if (ret < 0) {
		e_error(coi_ctx->user->event,
			"Failed to read COI configuration: %s",
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		coi_config_write_list_index(coi_ctx, box,
					    uid_validity, uid_next, config_r);
		ret = 0;
	}
	mailbox_free(&box);
	return ret;
}

void coi_config_init_context(struct coi_context *coi_ctx)
{
	struct mail_index *list_index;

	if (!mailbox_list_index_get_index(coi_ctx->root_ns->list, &list_index))
		coi_ctx->list_index_ext_id = (uint32_t)-1;
	else {
		coi_ctx->list_index_ext_id =
			mail_index_ext_register(list_index, "coi-config",
				sizeof(struct coi_config_binary), 0, 0);
	}
}
