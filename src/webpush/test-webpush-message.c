/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "str.h"
#include "unichar.h"
#include "test-common.h"
#include "webpush-message.h"

#define TEST_COMMON_INPUT \
	.mailbox_vname = "INBOX", \
	.uid_validity = 1, \
	.uid = 2, \
	.date = -1
#define TEST_COMMON_OUTPUT_PREFIX \
	"{\"folder\":\"INBOX\"," \
	"\"uidvalidity\":1," \
	"\"uid\":2,"

#define TEXT10 "1234567890"
#define TEXT50 TEXT10 TEXT10 TEXT10 TEXT10 TEXT10
#define TEXT100 TEXT50 TEXT50
#define TEXT500 TEXT100 TEXT100 TEXT100 TEXT100 TEXT100
#define TEXT1000 TEXT500 TEXT500

#define IN_ESC10 "\"\"\"\"\""
#define IN_ESC50 IN_ESC10 IN_ESC10 IN_ESC10 IN_ESC10 IN_ESC10
#define IN_ESC100 IN_ESC50 IN_ESC50
#define OUT_ESC10 "\\\"\\\"\\\"\\\"\\\""
#define OUT_ESC50 OUT_ESC10 OUT_ESC10 OUT_ESC10 OUT_ESC10 OUT_ESC10
#define OUT_ESC100 OUT_ESC50 OUT_ESC50

static struct {
	struct webpush_message_input input;
	const char *output;
} tests[] = {
	/* test all fields, including escaping */
	{ .input = {
		.mailbox_vname = "box\"name",
		.uid_validity = 1234567890,
		.uid = 1122334455,
		.date = 1566042493,
		.hdr_from_address = "test \"local@example.com",
		.hdr_from_display_name = "test user\"name",
		.hdr_subject = "some \"subject\"",
		.hdr_message_id = "<\"msgid\"@example.com>",
		.chat_group_id = "group\"id",
		.hdr_content_type = "text/html; charset=\"iso-8859-1\"",
		.hdr_content_transfer_encoding = "broken\"value",
		.body = "body\"text",
	  },
	  .output = "{"
		"\"folder\":\"box\\\"name\","
		"\"uidvalidity\":1234567890,"
		"\"uid\":1122334455,"
		"\"date\":\"2019-08-17T11:48:13+00:00\","
		"\"from-email\":\"test \\\"local@example.com\","
		"\"from-name\":\"test user\\\"name\","
		"\"subject\":\"some \\\"subject\\\"\","
		"\"msg-id\":\"<\\\"msgid\\\"@example.com>\","
		"\"group-id\":\"group\\\"id\","
		"\"content-type\":\"text/html; charset=\\\"iso-8859-1\\\"\","
		"\"content-encoding\":\"broken\\\"value\","
		"\"content\":\"body\\\"text\"}"
	},

	/* EAI UTF-8 in From header */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_from_address = "p\xC3\xA4ivi@example.com",
		.hdr_from_display_name = "P\xC3\xA4ivi Smith",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"from-email\":\"p\xC3\xA4ivi@example.com\","
		"\"from-name\":\"P\xC3\xA4ivi Smith\"}"
	},

	/* UTF-8 in subject */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "P\xC3\xA4ivi Smith",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\"P\xC3\xA4ivi Smith\"}"
	},
	/* UTF-8 in subject getting truncated */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"123456 P\xC3\xA4ivi",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"123456 P\xC3\xA4"UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"1234567 P\xC3\xA4ivi",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"1234567 P"UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"12345678 P\xC3\xA4ivi",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"12345678 P"UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"123456789 P\xC3\xA4ivi",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"123456789 "UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	/* Escape in subject getting truncated */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"1234567 \"",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"1234567 \\\"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"12345678 \"",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT50 TEXT10 TEXT10 TEXT10 TEXT10"12345678 "UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},

	/* Large From */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_from_address = TEXT50 TEXT10 TEXT10 TEXT10"@1234567.example.com",
		.hdr_from_display_name = TEXT100,
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"from-email\":\""TEXT50 TEXT10 TEXT10 TEXT10"@1234567.example.com\","
		"\"from-name\":\""TEXT100"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_from_address = TEXT50 TEXT10 TEXT10 TEXT10"@12345678.example.com",
		.hdr_from_display_name = TEXT100"x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"from-email\":\""TEXT50 TEXT10 TEXT10 TEXT10"@12345678.example.co"UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\","
		"\"from-name\":\""TEXT100 UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},

	/* Large Subject */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT100,
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT100"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = TEXT100"x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""TEXT100 UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = IN_ESC100"x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\""OUT_ESC100 UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},

	/* Large Message-ID */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_message_id = TEXT100,
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"msg-id\":\""TEXT100"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_message_id = TEXT100"x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"msg-id\":\""TEXT100 UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_message_id = IN_ESC100"x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"msg-id\":\""OUT_ESC100 UNICODE_HORIZONTAL_ELLIPSIS_CHAR_UTF8"\"}"
	},

	/* Large group */
	{ .input = {
		TEST_COMMON_INPUT,
		.chat_group_id = TEXT100,
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX"\"group-id\":\""TEXT100"\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.chat_group_id = TEXT100"1",
		.body = "x",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX"\"content\":\"x\"}"
	},

	/* Large body */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "foo",
		.body = TEXT1000 TEXT1000 TEXT1000 TEXT500 TEXT100 TEXT100 TEXT100 TEXT100 TEXT10 TEXT10 "12",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
	    "\"subject\":\"foo\","
	    "\"content\":\""TEXT1000 TEXT1000 TEXT1000 TEXT500 TEXT100 TEXT100 TEXT100 TEXT100 TEXT10 TEXT10 "12\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "foo",
		.body = TEXT1000 TEXT1000 TEXT1000 TEXT500 TEXT100 TEXT100 TEXT100 TEXT100 TEXT10 TEXT10 "123",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
	    "\"subject\":\"foo\"}"
	},

	/* Default Content-Type */
#define TEXT_COMMON_DEFAULT_CONTENT_TYPE(ct) \
	{ .input = { \
		TEST_COMMON_INPUT, \
		.hdr_subject = "x", \
		.body = "y", \
		.hdr_content_type = ct, \
	  }, \
	  .output = TEST_COMMON_OUTPUT_PREFIX \
		"\"subject\":\"x\"," \
		"\"content\":\"y\"}" \
	}
#define TEXT_COMMON_NOT_DEFAULT_CONTENT_TYPE(ct) \
	{ .input = { \
		TEST_COMMON_INPUT, \
		.hdr_subject = "x", \
		.body = "y", \
		.hdr_content_type = ct, \
	  }, \
	  .output = TEST_COMMON_OUTPUT_PREFIX \
		"\"subject\":\"x\"," \
		"\"content-type\":"# ct"," \
		"\"content\":\"y\"}" \
	}
	TEXT_COMMON_DEFAULT_CONTENT_TYPE("teXt/Plain"),
	TEXT_COMMON_DEFAULT_CONTENT_TYPE("teXt/Plain; Charset=Utf-8"),
	TEXT_COMMON_DEFAULT_CONTENT_TYPE("TEXT/PLAIN; Charset=Utf8"),
	TEXT_COMMON_DEFAULT_CONTENT_TYPE("text/plain; Charset=ascii"),
	TEXT_COMMON_DEFAULT_CONTENT_TYPE("teXt/Plain; Charset=us-ascii"),
	TEXT_COMMON_NOT_DEFAULT_CONTENT_TYPE("text/plain; charset=ascii-foo"),
	TEXT_COMMON_NOT_DEFAULT_CONTENT_TYPE("text/plain; charset=us-ascii; format=flowed"),
	TEXT_COMMON_NOT_DEFAULT_CONTENT_TYPE("text/plain; format=flowed; charset=us-ascii"),

	/* Default Content-Transfer-Encoding */
#define TEXT_COMMON_DEFAULT_CTE(cte) \
	{ .input = { \
		TEST_COMMON_INPUT, \
		.hdr_subject = "x", \
		.body = "y", \
		.hdr_content_transfer_encoding = cte, \
	  }, \
	  .output = TEST_COMMON_OUTPUT_PREFIX \
		"\"subject\":\"x\"," \
		"\"content\":\"y\"}" \
	}
	TEXT_COMMON_DEFAULT_CTE("7bit"),
	TEXT_COMMON_DEFAULT_CTE("8bit"),
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "x",
		.body = "y",
		.hdr_content_transfer_encoding = "quoted-printable",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\"x\","
		"\"content-encoding\":\"quoted-printable\","
		"\"content\":\"y\"}"
	},

	/* Content-Type / Content-Encoding has no limits alone,
	   but they must not make the message too large */
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "x",
		.hdr_content_type = TEXT1000 TEXT1000,
		.hdr_content_transfer_encoding = TEXT1000,
		.body = TEXT500 TEXT100 TEXT100 TEXT100 TEXT50 TEXT10 TEXT10 TEXT10"1234",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\"x\","
		"\"content-type\":\""TEXT1000 TEXT1000"\","
		"\"content-encoding\":\""TEXT1000"\","
		"\"content\":\""TEXT500 TEXT100 TEXT100 TEXT100 TEXT50 TEXT10 TEXT10 TEXT10"1234\"}"
	},
	{ .input = {
		TEST_COMMON_INPUT,
		.hdr_subject = "x",
		.hdr_content_type = TEXT1000 TEXT1000,
		.hdr_content_transfer_encoding = TEXT1000,
		.body = TEXT500 TEXT100 TEXT100 TEXT100 TEXT50 TEXT10 TEXT10 TEXT10"12345",
	  },
	  .output = TEST_COMMON_OUTPUT_PREFIX
		"\"subject\":\"x\"}"
	},
};

static void test_webpush_message(void)
{
	string_t *str = t_str_new(1024);

	test_begin("webpush message");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		webpush_message_write(str, &tests[i].input);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_webpush_message,
		NULL
	};

	env_put("TZ=UTC");
	return test_run(test_functions);
}
