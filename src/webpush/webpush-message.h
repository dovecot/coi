#ifndef WEBPUSH_MESSAGE_H
#define WEBPUSH_MESSAGE_H

#define WEBPUSH_MSG_MAX_ENCRYPTED_SIZE 4096
#define WEBPUSH_MSG_MAX_PLAINTEXT_LEN \
	(WEBPUSH_MSG_MAX_ENCRYPTED_SIZE - 103)

struct webpush_message_input {
	const char *mailbox_vname;
	uint32_t uid_validity;
	uint32_t uid;
	time_t date;

	const char *hdr_from_address;
	const char *hdr_from_display_name;
	const char *hdr_subject;
	const char *hdr_message_id;
	const char *chat_group_id;

	const char *hdr_content_type;
	const char *hdr_content_transfer_encoding;
	const char *body;
};

void webpush_message_write(string_t *str, const struct webpush_message_input *input);

#endif
