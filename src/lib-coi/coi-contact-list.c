/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-header-filter.h"
#include "message-header-parser.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "coi-contact.h"
#include "coi-contact-list.h"

struct coi_contact_transaction {
	struct coi_contact_list *list;
	struct mailbox_transaction_context *trans;
};

struct coi_contact_list {
	struct mailbox *box;
};

struct coi_contact_list *coi_contact_list_init_mailbox(struct mailbox *box)
{
	struct coi_contact_list *list;

	list = i_new(struct coi_contact_list, 1);
	list->box = box;
	return list;
}

void coi_contact_list_deinit(struct coi_contact_list **_list)
{
	struct coi_contact_list *list = *_list;

	i_free(list);
}

struct coi_contact_transaction *
coi_contact_transaction_begin(struct coi_contact_list *list)
{
	struct coi_contact_transaction *trans;

	trans = i_new(struct coi_contact_transaction, 1);
	trans->list = list;
	trans->trans = mailbox_transaction_begin(list->box,
		MAILBOX_TRANSACTION_FLAG_EXTERNAL, "COI transaction");
	return trans;
}

void coi_contact_transaction_commit(struct coi_contact_transaction **_trans)
{
	struct coi_contact_transaction *trans = *_trans;

	if (*_trans == NULL)
		return;

	*_trans = NULL;
	if (trans->trans != NULL) {
		if (mailbox_transaction_commit(&trans->trans) < 0) {
			i_error("COI contact mailbox transaction commit failed: %s",
				mailbox_get_last_error(trans->list->box, NULL));
		}
	}
	i_free(trans);
}

struct mailbox *
coi_contact_transaction_get_mailbox(struct coi_contact_transaction *trans)
{
	return trans->list->box;
}

static int
coi_contact_list_find_full(struct coi_contact_transaction *trans,
			   const char *from_normalized,
			   const char *to_normalized,
			   const char *token,
			   struct coi_contact **contact_r,
			   struct coi_token **token_r,
			   struct mail_storage **error_storage_r)
{
	struct mailbox *box = trans->list->box;
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	struct mail *mail;
	struct mailbox_header_lookup_ctx *wanted_headers;
	const char *const wanted_header_strings[] = {
		COI_HDR_TOKEN_IN,
		COI_HDR_TOKEN_OUT,
		NULL
	};
	const char *hash, *const *values;

	*contact_r = NULL;
	if (token_r != NULL)
		*token_r = NULL;
	*error_storage_r = NULL;

	search_args = mail_search_build_init();
	if (token != NULL) {
		/* find a header which has the wanted token */
		arg = mail_search_build_add(search_args, SEARCH_HEADER);
		arg->hdr_field_name = COI_HDR_TOKEN_IN;
		arg->value.str = token;
		hash = coi_contact_generate_hash(from_normalized, to_normalized);
	} else {
		/* find user by hash of the address */
		i_assert(token_r == NULL);
		hash = coi_contact_generate_hash(from_normalized, NULL);
		arg = mail_search_build_add(search_args, SEARCH_HEADER);
		arg->hdr_field_name = COI_HDR_FROM_HASH;
		arg->value.str = hash;
	}

	/* Search the hash from the token headers. This lookup could be
	   optimized by e.g. fts plugin. */
	wanted_headers = mailbox_header_lookup_init(box, wanted_header_strings);
	search_ctx = mailbox_search_init(trans->trans, search_args, NULL,
					 0, wanted_headers);
	mailbox_header_lookup_unref(&wanted_headers);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		/* parse and verify that this mail actually has the wanted
		   token. */
		struct coi_contact *contact;

		if (coi_contact_parse(mail, &contact) < 0) {
			*error_storage_r = mailbox_get_storage(box);
			break;
		}
		if (token == NULL) {
			/* verify only the From hash */
			if (mail_get_headers(mail, COI_HDR_FROM_HASH, &values) < 0) {
				*error_storage_r = mailbox_get_storage(mail->box);
				break;
			}
			if (str_array_find(values, hash))
				break;
			continue;
		}
		/* verify that From+To hash matches, and also that the contact
		   token has a matching token */
		if (coi_contact_token_in_find_hash(contact, hash) != NULL) {
			mailbox_search_mail_detach(search_ctx, mail);
			if (token_r != NULL)
				*token_r = coi_contact_token_in_find(contact, token);
			*contact_r = contact;
			break;
		}
	}

	if (mailbox_search_deinit(&search_ctx) < 0)
		*error_storage_r = mailbox_get_storage(box);
	return *error_storage_r != NULL ? -1 : 0;
}

int coi_contact_list_find(struct coi_contact_transaction *trans,
			  const char *from_normalized,
			  const char *to_normalized,
			  struct coi_contact **contact_r,
			  struct mail_storage **error_storage_r)
{
	return coi_contact_list_find_full(trans, from_normalized, to_normalized,
					  NULL, contact_r, NULL,
					  error_storage_r);
}

int coi_contact_list_find_token(struct coi_contact_transaction *trans,
				const char *from_normalized,
				const char *to_normalized,
				const char *token, time_t timestamp,
				struct coi_contact **contact_r,
				struct coi_token **token_r,
				struct mail_storage **error_storage_r)
{
	const char *reason;

	if (coi_contact_list_find_full(trans, from_normalized, to_normalized,
				       token, contact_r, token_r,
				       error_storage_r) < 0)
		return -1;
	if (*token_r == NULL)
		return 0;

	return coi_token_verify_validity(*token_r, timestamp, &reason) ? 1 : 0;
}

static void
coi_contact_header_callback(struct header_filter_istream *input,
			    struct message_header_line *hdr,
			    bool *matched, struct coi_contact_update *update)
{
	struct coi_token *const *tokenp;
	string_t *str;

	if (hdr == NULL || !hdr->eoh)
		return;

	/* Add all the COI-Token and COI-MyToken headers to the end of
	   the headers */
	*matched = TRUE;
	str = t_str_new(512);
	array_foreach(&update->contact.tokens_in, tokenp) {
		str_append(str, COI_HDR_TOKEN_IN": ");
		coi_token_append(str, *tokenp);
		str_append_c(str, '\n');
	}
	array_foreach(&update->contact.tokens_out, tokenp) {
		str_append(str, COI_HDR_TOKEN_OUT": ");
		coi_token_append(str, *tokenp);
		str_append_c(str, '\n');
	}
	i_stream_header_filter_add(input, str_data(str), str_len(str));
}

static struct istream *
coi_contact_create_istream(struct coi_contact_update *update)
{
	const char *from_hash =
		coi_contact_generate_hash(update->create_from_normalized, NULL);

	const char *str = t_strdup_printf(
		COI_HDR_FROM_HASH": %s\n"
		"Subject: Contact\n"
		"\n",
		from_hash);
	return i_stream_create_copy_from_data(str, strlen(str));
}

static int
coi_contact_update_istream(struct coi_contact_update *update,
			   struct istream **input_r)
{
	struct istream *input, *mail_input;
	const char *const coi_exclude_headers[] = {
		COI_HDR_TOKEN_IN,
		COI_HDR_TOKEN_OUT,
		NULL
	};

	if (update->contact.mail == NULL)
		mail_input = coi_contact_create_istream(update);
	else if (mail_get_stream_because(update->contact.mail, NULL, NULL,
					 "COI contact update", &mail_input) < 0)
		return -1;

	/* use the original mail, but rewrite COI-Token headers */
	input = i_stream_create_header_filter(mail_input,
					      HEADER_FILTER_EXCLUDE |
					      HEADER_FILTER_ADD_MISSING_EOH,
					      coi_exclude_headers, 1,
					      coi_contact_header_callback,
					      update);
	i_stream_unref(&mail_input);

	*input_r = input;
	return 0;
}

static int
coi_contact_list_write(struct coi_contact_transaction *trans,
		       struct coi_contact_update *update)
{
	struct mail_save_context *save_ctx;
	struct istream *contact_input;
	bool save_failed = FALSE;
	int ret;

	if (coi_contact_update_istream(update, &contact_input) < 0)
		return -1;

	save_ctx = mailbox_save_alloc(trans->trans);
	if (mailbox_save_begin(&save_ctx, contact_input) < 0)
		ret = -1;
	else do {
		if (mailbox_save_continue(save_ctx) < 0) {
			save_failed = TRUE;
			ret = -1;
			break;
		}
	} while ((ret = i_stream_read(contact_input)) > 0);
	i_assert(ret == -1);

	if (contact_input->stream_errno != 0) {
		mailbox_set_critical(trans->list->box, "read(contact) failed: %s",
				     i_stream_get_error(contact_input));
		ret = -1;
	} else if (save_failed || save_ctx == NULL) {
		ret = -1;
	} else if (mailbox_save_finish(&save_ctx) < 0) {
		ret = -1;
	} else if (mailbox_transaction_commit(&trans->trans) < 0) {
		ret = -1;
	} else if (update->contact.mail != NULL) {
		/* updating a contact: saving was successful.
		   now expunge the old mail. */
		struct mail *old_mail = mail_alloc(trans->trans, 0, NULL);
		if (mail_set_uid(old_mail, update->contact.mail->uid))
			mail_expunge(old_mail);
		ret = 0;
	} else {
		/* created a new contact successfully */
		ret = 0;
	}
	if (save_ctx != NULL)
		mailbox_save_cancel(&save_ctx);
	if (trans->trans != NULL)
		mailbox_transaction_rollback(&trans->trans);
	i_assert(contact_input->eof);
	i_stream_unref(&contact_input);
	return ret;
}

int coi_contact_list_update(struct coi_contact_transaction **_trans,
			    struct coi_contact_update **_update,
			    struct mail_storage **error_storage_r)
{
	struct coi_contact_transaction *trans = *_trans;
	struct coi_contact_update *update = *_update;

	*_trans = NULL;
	*_update = NULL;
	*error_storage_r = NULL;

	if (update->failed) {
		/* failed to parse headers in coi_contact_update_begin() */
		*error_storage_r = mailbox_get_storage(trans->list->box);
	} else if (update->changed) {
		if (coi_contact_list_write(trans, update) < 0)
			*error_storage_r = mailbox_get_storage(trans->list->box);
	}

	coi_contact_update_abort(&update);
	coi_contact_transaction_commit(&trans);
	return *error_storage_r != NULL ? -1 : 0;
}
