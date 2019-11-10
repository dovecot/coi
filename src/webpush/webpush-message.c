/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "iso8601-date.h"
#include "json-parser.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "charset-utf8.h"
#include "webpush-message.h"

#define WEBPUSH_GROUP_ID_MAX_LEN 100
#define WEBPUSH_VALUE_MAX_LEN 100

static void
webpush_notify_append_limited(string_t *str, const char *key, const char *value)
{
	str_printfa(str, ",\"%s\":\"", key);
	size_t value_pos = str_len(str);
	json_append_escaped(str, value);
	if (str_len(str) - value_pos > WEBPUSH_VALUE_MAX_LEN) {
		size_t len = value_pos + WEBPUSH_VALUE_MAX_LEN;
		/* remove partial UTF8 chars */
		while (!UTF8_IS_START_SEQ(str_data(str)[len]))
			len--;
		str_truncate(str, len);

		/* remove partial escape chars */
		const char *p = strchr(str_c(str), '\\');
		if (p != NULL) {
			if (p[1] == '\0' ||
			    (p[1] == 'u' && strlen(p+2) < 4))
				str_truncate(str, p - str_c(str));
		}

		str_append(str, UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8);
	}
	str_append(str, "\"");
}

static bool webpush_is_default_content_type(const char *hdr_content_type)
{
	struct rfc822_parser_context parser;
	string_t *content_type = t_str_new(64);
	const char *const *params;

	/* must be text/plain */
	rfc822_parser_init(&parser, (const unsigned char *)hdr_content_type,
			   strlen(hdr_content_type), NULL);
	rfc822_skip_lwsp(&parser);

	if (rfc822_parse_content_type(&parser, content_type) < 0)
		return FALSE;
	if (strcasecmp(str_c(content_type), "text/plain") != 0)
		return FALSE;

	/* only charset=utf8 (or compatible) is allowed */
	rfc2231_parse(&parser, &params);
	for (; *params != NULL; params += 2) {
		if (strcasecmp(params[0], "charset") == 0) {
			if (!charset_is_utf8(params[1]))
				return FALSE;
		} else {
			return FALSE;
		}
	}
	rfc822_parser_deinit(&parser);
	return TRUE;
}

static bool webpush_is_default_cte(const char *hdr_content_transfer_encoding)
{
	return strcasecmp(hdr_content_transfer_encoding, "7bit") == 0 ||
		strcasecmp(hdr_content_transfer_encoding, "8bit") == 0;
}

void webpush_message_write(string_t *str, const struct webpush_message_input *input)
{
	str_append(str, "{\"folder\":\"");
	json_append_escaped(str, input->mailbox_vname);
	str_printfa(str, "\",\"uidvalidity\":%u,\"uid\":%u",
		    input->uid_validity, input->uid);
	if (input->date != -1) {
		str_printfa(str, ",\"date\":\"%s\"",
			    iso8601_date_create(input->date));
	}
	if (input->hdr_from_address != NULL)
		webpush_notify_append_limited(str, "from-email", input->hdr_from_address);
	if (input->hdr_from_display_name != NULL)
		webpush_notify_append_limited(str, "from-name", input->hdr_from_display_name);
	if (input->hdr_subject != NULL)
		webpush_notify_append_limited(str, "subject", input->hdr_subject);
	if (input->hdr_message_id != NULL)
		webpush_notify_append_limited(str, "msg-id", input->hdr_message_id);
	if (input->chat_group_id != NULL) {
		size_t orig_pos = str_len(str);
		str_append(str, ",\"group-id\":\"");
		size_t group_value_pos = str_len(str);
		json_append_escaped(str, input->chat_group_id);
		size_t group_value_len = str_len(str) - group_value_pos;
		str_append(str, "\"");
		/* sanity check to make sure it's not too large */
		if (group_value_len > WEBPUSH_GROUP_ID_MAX_LEN)
			str_truncate(str, orig_pos);
	}
	i_assert(str_len(str) < WEBPUSH_MSG_MAX_PLAINTEXT_LEN);
	size_t pre_body_pos = str_len(str);
	if (input->body != NULL) {
		/* Content-Type and Content-Transfer-Encoding themselves don't
		   have any limits here. Together with body either they're all
		   sent or none of them are sent. */
		if (input->hdr_content_type != NULL &&
		    !webpush_is_default_content_type(input->hdr_content_type)) {
			str_append(str, ",\"content-type\":\"");
			json_append_escaped(str, input->hdr_content_type);
			str_append(str, "\"");
		}
		if (input->hdr_content_transfer_encoding != NULL &&
		    !webpush_is_default_cte(input->hdr_content_transfer_encoding)) {
			str_append(str, ",\"content-encoding\":\"");
			json_append_escaped(str, input->hdr_content_transfer_encoding);
			str_append(str, "\"");
		}
		str_append(str, ",\"content\":\"");
		json_append_escaped(str, input->body);
		str_append(str, "\"");
	}
	if (str_len(str) >= WEBPUSH_MSG_MAX_PLAINTEXT_LEN) {
		/* Body would make the message too large. Don't send it. */
		str_truncate(str, pre_body_pos);
	}
	str_append(str, "}");
	i_assert(str_len(str) <= WEBPUSH_MSG_MAX_PLAINTEXT_LEN);
}
