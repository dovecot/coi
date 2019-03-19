/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha3.h"
#include "base64.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "message-size.h"
#include "message-header-parser.h"
#include "mail-storage-private.h"
#include "coi-secret.h"
#include "coi-contact.h"

#include <time.h>

/* Characters that must not exist in the COI-Token header's fields.
   The '-' character is a separator between fields. */
#define COI_TOKEN_DISALLOWED_CHARS "-\r\n"

#define COI_TOKEN_FIELD_HASH_SECRET "secret"
#define COI_TOKEN_FIELD_CREATED "created"
#define COI_TOKEN_FIELD_VALIDITY "validity"
#define COI_TOKEN_FIELD_HASH "hash"
#define COI_TOKEN_FIELD_HASH_ALGO "hash_algo"

const char *
coi_contact_generate_hash(const char *from_normalized,
			  const char *to_normalized)
{
	struct sha3_ctx ctx;
	unsigned char digest[SHA256_RESULTLEN];
	string_t *digest_str;

	sha3_256_init(&ctx);
	sha3_loop(&ctx, from_normalized, strlen(from_normalized));
	if (to_normalized != NULL) {
		sha3_loop(&ctx, ":", 1);
		sha3_loop(&ctx, to_normalized, strlen(to_normalized));
	}
	sha3_256_result(&ctx, digest);

	digest_str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(digest)));
	base64_encode(digest, sizeof(digest), digest_str);
	/* drop trailing '=' */
	while (str_data(digest_str)[str_len(digest_str)-1] == '=')
		str_truncate(digest_str, str_len(digest_str)-1);
	return str_c(digest_str);
}

struct coi_token *coi_token_new(pool_t pool)
{
	struct coi_token *token;

	token = p_new(pool, struct coi_token, 1);
	token->create_time = time(NULL);
	token->hash_algo = COI_HASH_ALGO_DEFAULT;
	p_array_init(&token->options, pool, 4);
	return token;
}

int coi_token_parse(const char *token_string, pool_t pool,
		    struct coi_token **token_r, const char **error_r)
{
	struct coi_token *token;
	struct coi_token_option option;
	const char *const *args = t_strsplit(token_string, "-");

	if (null_strcmp(args[0], "1") != 0) {
		/* unsupported major version format */
		*error_r = t_strdup_printf("Unsupported version '%s'", args[0]);
		return -1;
	}

	token = coi_token_new(pool);
	token->token_string = p_strdup(pool, token_string);
	for (unsigned int i = 1; args[i] != NULL; i++) {
		const char *key, *value = strchr(args[i], ':');
		if (value != NULL)
			key = t_strdup_until(args[i], value++);
		else {
			key = args[i];
			value = "";
		}
		if (strcmp(key, COI_TOKEN_FIELD_HASH_SECRET) == 0)
			token->secret = p_strdup(pool, value);
		else if (strcmp(key, COI_TOKEN_FIELD_CREATED) == 0) {
			if (str_to_time(value, &token->create_time) < 0 ||
			    token->create_time <= 0) {
				*error_r = t_strdup_printf(
					"Invalid '%s': '%s'", key, value);
				return -1;
			}
		} else if (strcmp(key, COI_TOKEN_FIELD_VALIDITY) == 0) {
			if (str_to_uint(value, &token->validity_secs) < 0 ||
			    token->validity_secs == 0) {
				*error_r = t_strdup_printf(
					"Invalid '%s': '%s'", key, value);
				return -1;
			}
		} else if (strcmp(key, COI_TOKEN_FIELD_HASH) == 0) {
			token->from_to_normalized_hash = p_strdup(pool, value);
		} else if (strcmp(key, COI_TOKEN_FIELD_HASH_ALGO) == 0) {
			if (strcmp(key, "sha3-256") == 0)
				token->hash_algo = COI_HASH_ALGO_SHA3_256;
			else {
				*error_r = t_strdup_printf(
					"Unsupported %s '%s'", key, value);
				return -1;
			}
		} else {
			i_zero(&option);
			option.key = p_strdup(pool, key);
			option.value = p_strdup(pool, value);
			array_append(&token->options, &option, 1);
		}
	}
	if (token->secret == NULL) {
		*error_r = "Missing '"COI_TOKEN_FIELD_HASH_SECRET"' field";
		return -1;
	}
	if (token->create_time == 0) {
		*error_r = "Missing '"COI_TOKEN_FIELD_CREATED"' field";
		return -1;
	}
	if (token->validity_secs == 0) {
		*error_r = "Missing '"COI_TOKEN_FIELD_VALIDITY"' field";
		return -1;
	}
	if (token->from_to_normalized_hash == NULL) {
		*error_r = "Missing '"COI_TOKEN_FIELD_HASH"' field";
		return -1;
	}
	*token_r = token;
	return 0;
}

static int
coi_contact_parse_headers(struct coi_contact *contact, const char *hdr_name,
			  ARRAY_TYPE(coi_token) *parsed_tokens)
{
	struct mail_private *pmail = (struct mail_private *)contact->mail;
	struct coi_token *token;
	const char *const *tokens, *error;

	if (mail_get_headers(contact->mail, hdr_name, &tokens) < 0)
		return -1;

	for (unsigned int i = 0; tokens[i] != NULL; i++) {
		if (coi_token_parse(tokens[i], pmail->data_pool,
				    &token, &error) < 0 &&
		    contact->error == NULL) {
			contact->error = p_strdup_printf(pmail->data_pool,
				"Invalid token: %s", error);
		} else {
			array_append(parsed_tokens, &token, 1);
		}
	}
	return 0;
}

int coi_contact_parse(struct mail *mail, struct coi_contact **contact_r)
{
	struct mail_private *pmail = (struct mail_private *)mail;
	struct coi_contact *contact;

	contact = p_new(pmail->data_pool, struct coi_contact, 1);
	contact->mail = mail;

	if (coi_contact_parse_headers(contact, COI_HDR_TOKEN_IN,
				      &contact->tokens_in) < 0)
		return -1;
	if (coi_contact_parse_headers(contact, COI_HDR_TOKEN_OUT,
				      &contact->tokens_out) < 0)
		return -1;

	*contact_r = contact;
	return 0;
}

void coi_token_append(string_t *dest, const struct coi_token *token)
{
	const struct coi_token_option *option;

	i_assert(token->hash_algo == COI_HASH_ALGO_SHA3_256);

	str_printfa(dest, "1-"COI_TOKEN_FIELD_CREATED":%"PRIdTIME_T,
		    token->create_time);
	str_printfa(dest, "-"COI_TOKEN_FIELD_VALIDITY":%u",
		    token->validity_secs);
	str_printfa(dest, "-"COI_TOKEN_FIELD_HASH":%s",
		    token->from_to_normalized_hash);
	array_foreach(&token->options, option)
		str_printfa(dest, "-%s:%s", option->key, option->value);
	/* keep secret the last one, so this function can be used to generate
	   the secret. */
	str_printfa(dest, "-"COI_TOKEN_FIELD_HASH_SECRET":%s", token->secret);
}

static void
coi_contact_update_parse_headers(struct coi_contact_update *update,
				 const char *hdr_name,
				 ARRAY_TYPE(coi_token) *parsed_tokens)
{
	struct mail_private *pmail =
		(struct mail_private *)update->contact.mail;
	struct coi_token *token;
	const char *const *tokens, *error;

	if (mail_get_headers(update->contact.mail, hdr_name, &tokens) < 0) {
		update->failed = TRUE;
		return;
	}

	/* Parse contacts, skipping over invalid tokens.
	   Preserve tokens with unknown versions. */
	for (unsigned int i = 0; tokens[i] != NULL; i++) {
		if (coi_token_parse(tokens[i], pmail->data_pool,
				    &token, &error) < 0) {
			/* broken token - ignore it here so it gets dropped
			   when rewriting */
		} else {
			array_append(parsed_tokens, &token, 1);
		}
	}
}

static struct coi_contact_update *
coi_contact_update_alloc(struct mailbox *box)
{
	struct coi_contact_update *update;
	pool_t pool;

	pool = pool_alloconly_create("coi contact update", 1024);
	update = p_new(pool, struct coi_contact_update, 1);
	update->pool = pool;
	update->box = box;

	p_array_init(&update->contact.tokens_in, update->pool, 8);
	p_array_init(&update->contact.tokens_out, update->pool, 8);
	return update;
}

struct coi_contact_update *coi_contact_update_begin(struct mail *mail)
{
	struct coi_contact_update *update;

	update = coi_contact_update_alloc(mail->box);
	update->contact.mail = mail;
	coi_contact_update_parse_headers(update, COI_HDR_TOKEN_IN,
					 &update->contact.tokens_in);
	coi_contact_update_parse_headers(update, COI_HDR_TOKEN_OUT,
					 &update->contact.tokens_out);
	return update;
}

struct coi_contact_update *
coi_contact_create_begin(struct mailbox *box, const char *from_normalized)
{
	struct coi_contact_update *update;

	update = coi_contact_update_alloc(box);
	update->create_from_normalized =
		p_strdup(update->pool, from_normalized);
	return update;
}

static struct coi_token *
coi_contact_token_find_full(ARRAY_TYPE(coi_token) *tokens,
			    const char *token_string, unsigned int *idx_r)
{
	struct coi_token *const *tokenp;

	array_foreach_modifiable(tokens, tokenp) {
		if (strcmp((*tokenp)->token_string, token_string) == 0) {
			*idx_r = array_foreach_idx(tokens, tokenp);
			return *tokenp;
		}
	}
	*idx_r = UINT_MAX;
	return NULL;
}

static struct coi_token *
coi_contact_token_in_find_full(struct coi_contact *contact,
			       const char *token_string, unsigned int *idx_r)
{
	return coi_contact_token_find_full(&contact->tokens_in,
					   token_string, idx_r);
}

static struct coi_token *
coi_contact_token_out_find_full(struct coi_contact *contact,
				const char *token_string, unsigned int *idx_r)
{
	return coi_contact_token_find_full(&contact->tokens_in,
					   token_string, idx_r);
}

struct coi_token *
coi_contact_token_in_find(struct coi_contact *contact, const char *token)
{
	unsigned int idx;
	return coi_contact_token_in_find_full(contact, token, &idx);
}

static struct coi_token *
coi_tokens_find_hash(const ARRAY_TYPE(coi_token) *tokens, const char *hash)
{
	struct coi_token *const *tokenp;
	struct coi_token *newest_token = NULL;

	array_foreach_modifiable(tokens, tokenp) {
		if (strcmp((*tokenp)->from_to_normalized_hash, hash) == 0 &&
		    (newest_token == NULL ||
		     (*tokenp)->create_time > newest_token->create_time))
			newest_token = *tokenp;
	}
	return newest_token;
}

struct coi_token *
coi_contact_token_in_find_hash(struct coi_contact *contact, const char *hash)
{
	return coi_tokens_find_hash(&contact->tokens_in, hash);
}

struct coi_token *
coi_contact_token_out_find_hash(struct coi_contact *contact, const char *hash)
{
	return coi_tokens_find_hash(&contact->tokens_out, hash);
}

static struct coi_token_option *
coi_option_find(const struct coi_token *token, const char *key)
{
	struct coi_token_option *option;

	array_foreach_modifiable(&token->options, option) {
		if (strcmp(option->key, key) == 0)
			return option;
	}
	return NULL;
}

static void
coi_contact_update_token(struct coi_contact_update *update,
			 struct coi_token *old_token,
			 const struct coi_token *token)
{
	const struct coi_token_option *option;
	struct coi_token_option *old_option;

	i_assert(token->secret != NULL && token->secret[0] != '\0');
	i_assert(strpbrk(token->secret, COI_TOKEN_DISALLOWED_CHARS) == NULL);
	i_assert(token->create_time > 0);
	i_assert(token->validity_secs > 0);
	i_assert(token->from_to_normalized_hash != NULL);
	i_assert(strpbrk(token->from_to_normalized_hash, COI_TOKEN_DISALLOWED_CHARS) == NULL);
	i_assert(token->hash_algo == COI_HASH_ALGO_SHA3_256);

	if (old_token->secret == NULL ||
	    strcmp(old_token->secret, token->secret) != 0) {
		old_token->secret = p_strdup(update->pool, token->secret);
		update->changed = TRUE;
	}
	if (old_token->create_time != token->create_time) {
		old_token->create_time = token->create_time;
		update->changed = TRUE;
	}
	if (old_token->validity_secs != token->validity_secs) {
		old_token->validity_secs = token->validity_secs;
		update->changed = TRUE;
	}
	if (old_token->from_to_normalized_hash == NULL ||
	    strcmp(old_token->from_to_normalized_hash,
		   token->from_to_normalized_hash) != 0) {
		old_token->from_to_normalized_hash =
			p_strdup(update->pool, token->from_to_normalized_hash);
		update->changed = TRUE;
	}
	if (old_token->hash_algo != token->hash_algo) {
		old_token->hash_algo = token->hash_algo;
		update->changed = TRUE;
	}
	/* add missing optional parameters */
	array_foreach(&token->options, option) {
		i_assert(option->key != NULL);
		i_assert(option->value != NULL);
		i_assert(strpbrk(option->key, COI_TOKEN_DISALLOWED_CHARS) == NULL);
		i_assert(strpbrk(option->value, COI_TOKEN_DISALLOWED_CHARS) == NULL);

		old_option = coi_option_find(old_token, option->key);
		if (old_option == NULL) {
			struct coi_token_option new_option = {
				.key = p_strdup(update->pool, option->key),
				.value = p_strdup(update->pool, option->value)
			};
			array_append(&old_token->options, &new_option, 1);
			update->changed = TRUE;
		} else if (strcmp(old_option->value, option->value) != 0) {
			old_option->value = p_strdup(update->pool, option->value);
			update->changed = TRUE;
		}
	}
	/* remove optional parameters that are no longer wanted */
	for (unsigned int i = array_count(&old_token->options); i > 0; i--) {
		option = array_idx(&old_token->options, i-1);
		if (coi_option_find(token, option->key) != NULL) {
			array_delete(&old_token->options, i-1, 1);
			update->changed = TRUE;
		}
	}

	/* rebuild the token_string */
	string_t *str = t_str_new(128);
	coi_token_append(str, token);
	if (null_strcmp(old_token->token_string, str_c(str)) != 0)
		old_token->token_string = p_strdup(update->pool, str_c(str));
}

static struct coi_token *
coi_contact_update_token_init(struct coi_contact_update *update,
			      const char *token_string)
{
	struct coi_token *token;

	token = p_new(update->pool, struct coi_token, 1);
	token->token_string = p_strdup(update->pool, token_string);
	update->changed = TRUE;
	p_array_init(&token->options, update->pool, 4);
	return token;
}

void coi_contact_update_add_token_in(struct coi_contact_update *update,
				     const struct coi_token *token)
{
	struct coi_token *old_token;
	unsigned int idx;

	old_token = coi_contact_token_in_find_full(&update->contact,
						   token->token_string, &idx);
	if (old_token == NULL) {
		old_token = coi_contact_update_token_init(update, token->token_string);
		array_append(&update->contact.tokens_in, &old_token, 1);
	}
	coi_contact_update_token(update, old_token, token);
}

void coi_contact_update_add_token_out(struct coi_contact_update *update,
				      const struct coi_token *token)
{
	struct coi_token *old_token;
	unsigned int idx;

	old_token = coi_contact_token_out_find_full(&update->contact,
						    token->token_string, &idx);
	if (old_token == NULL) {
		old_token = coi_contact_update_token_init(update, token->token_string);
		array_append(&update->contact.tokens_out, &old_token, 1);
	}
	coi_contact_update_token(update, old_token, token);
}

void coi_contact_update_delete(struct coi_contact_update *update,
			       const char *token)
{
	unsigned int idx;

	if (coi_contact_token_in_find_full(&update->contact, token, &idx) != NULL) {
		array_delete(&update->contact.tokens_in, idx, 1);
		update->changed = TRUE;
	}
}

static int lmtp_coi_mail_bodies_equal(struct mail *mail1, struct mail *mail2,
				      struct istream **mail2_input_r)
{
	struct istream *input1, *input2;
	const unsigned char *data1, *data2;
	size_t size1, size2;
	struct message_size hdr_size;
	const char *errstr;
	enum mail_error error;
	int ret1, ret2;

	if (mail_get_stream(mail1, &hdr_size, NULL, &input1) < 0) {
		errstr = mailbox_get_last_error(mail1->box, &error);
		if (error != MAIL_ERROR_EXPUNGED)
			e_error(mail1->event, "Contact merge failed: "
				"Failed to read mail: %s", errstr);
		return -1;
	}
	i_stream_skip(input1, hdr_size.physical_size);

	if (mail_get_stream(mail2, &hdr_size, NULL, &input2) < 0) {
		errstr = mailbox_get_last_error(mail2->box, &error);
		if (error != MAIL_ERROR_EXPUNGED)
			e_error(mail2->event, "Contact merge failed: "
				"Failed to read mail: %s", errstr);
		return -1;
	}
	i_stream_skip(input2, hdr_size.physical_size);

	for (;;) {
		ret1 = i_stream_read_more(input1, &data1, &size1);
		ret2 = i_stream_read_more(input2, &data2, &size2);
		i_assert(ret1 != 0 && ret2 != 0);
		if (ret1 < 0 || ret2 < 0)
			break;

		size_t min_size = I_MIN(size1, size2);
		if (memcmp(data1, data2, min_size) != 0)
			return 0;
		i_stream_skip(input1, min_size);
		i_stream_skip(input2, min_size);
	}
	if (ret1 != ret2)
		return 0;
	i_assert(ret1 == -1);
	i_assert(input1->eof && input2->eof);

	if (input1->stream_errno != 0) {
		e_error(mail1->event, "Contact merge failed: "
			"Failed to read mail: %s", i_stream_get_error(input1));
		return -1;
	}
	if (input2->stream_errno != 0) {
		e_error(mail2->event, "Contact merge failed: "
			"Failed to read mail: %s", i_stream_get_error(input2));
		return -1;
	}
	*mail2_input_r = input2;
	return 1;
}

static void
coi_contact_update_try_merge_hdr(struct coi_contact_update *update,
				 const struct message_header_line *hdr)
{
	struct coi_token *token;
	const char *error;

	if (strcasecmp(hdr->name, COI_HDR_TOKEN_IN) == 0) {
		const char *token_string = t_strndup(hdr->full_value,
						     hdr->full_value_len);
		if (coi_token_parse(token_string, pool_datastack_create(),
				    &token, &error) == 0)
			coi_contact_update_add_token_in(update, token);
	}
	if (strcasecmp(hdr->name, COI_HDR_TOKEN_OUT) == 0) {
		const char *token_string = t_strndup(hdr->full_value,
						     hdr->full_value_len);
		if (coi_token_parse(token_string, pool_datastack_create(),
				    &token, &error) == 0)
			coi_contact_update_add_token_out(update, token);
	}
	/* FIXME: merge other headers also? */
}

void coi_contact_update_try_merge(struct coi_contact_update *update,
				  const struct coi_contact *old_contact)
{
	struct istream *old_input;
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	int ret;

	i_assert(update->contact.mail != NULL);

	/* If the messages bodies have exactly the same content, we can
	   merge the mails. Otherwise leave this to the COI client to
	   do the merging. The bodies might be encrypted, so we
	   might not be able to do the merging even if we wanted to. */
	ret = lmtp_coi_mail_bodies_equal(update->contact.mail,
					 old_contact->mail, &old_input);
	if (ret < 0) {
		/* Internal error - unknown result. Safest to treat
		   this as if they didn't match. */
		return;
	}
	if (ret == 0)
		return;

	/* FIXME: merge all headers and save them in the new mail */
	i_stream_seek(old_input, 0);
	parser = message_parse_header_init(old_input, NULL, 0);
	while (message_parse_header_next(parser, &hdr) > 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			continue;
		}
		T_BEGIN {
			coi_contact_update_try_merge_hdr(update, hdr);
		} T_END;
	}
	message_parse_header_deinit(&parser);
}

void coi_contact_update_abort(struct coi_contact_update **_update)
{
	struct coi_contact_update *update = *_update;

	*_update = NULL;
	pool_unref(&update->pool);
}

bool coi_token_verify_quick(const struct coi_secret_settings *set, time_t now,
			    const struct coi_token *token, bool *temp_r,
			    const char **error_r)
{
	/* FIXME: should we allow timestamps that are a bit into the future? */
	if (token->create_time > now) {
		*error_r = "Create timestamp is in the future";
		return FALSE;
	}
	if (now - token->create_time > token->validity_secs) {
		*error_r = "Token is expired";
		return FALSE;
	}

	switch (coi_secret_verify(set, token)) {
	case COI_SECRET_RESULT_NOTFOUND:
		*error_r = "Secret is not valid";
		return FALSE;
	case COI_SECRET_RESULT_TEMP:
		*temp_r = TRUE;
		return TRUE;
	case COI_SECRET_RESULT_PERM:
		*temp_r = FALSE;
		return TRUE;
	}
	i_unreached();
}
