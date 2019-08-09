/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "webpush-subscription.h"
#include "test-common.h"

static struct {
	const char *input;
	bool success;
	struct webpush_subscription subscription;
} tests[] = {
	/* invalid JSON */
	{ .input = "\"create_time\": \"2019-08-16T17:59:56Z\"", .success = FALSE },
	{ .input = "{ \"create_time\": \"2019-08-16T17:59:56Z\"", .success = FALSE },
	{ .input = "{ \"create_time\": \"2019-08-16T17:59:56Z\" }{}", .success = FALSE },

	/* create_time */
	{ .input = "{ \"create_time\": \"2019-08-16T17:59:56Z\" }",
	  .success = TRUE,
	  .subscription = { .create_time = 1565978396 },
	},
	{ .input = "{ \"create_time\": \"2019-08-16T17:59:56\" }", .success = FALSE },
	{ .input = "{ \"create_time\": \"12345678\" }", .success = FALSE },
	{ .input = "{ \"create_time\": 12345678 }", .success = FALSE },

	/* validation */
	{ .input = "{ \"validation\": \"foobar\" }",
	  .success = TRUE,
	  .subscription = { .validation = "foobar" },
	},
	{ .input = "{ \"validation\": false }", .success = FALSE },
	{ .input = "{ \"validation\": null }", .success = FALSE },

	/* client_name */
	{ .input = "{ \"client\": \"testclient\" }",
	  .success = TRUE,
	  .subscription = { .client_name = "testclient" },
	},
	{ .input = "{ \"client\": false }", .success = FALSE },
	{ .input = "{ \"client\": null }", .success = FALSE },

	/* device_name */
	{ .input = "{ \"device\": \"testdevice\" }",
	  .success = TRUE,
	  .subscription = { .device_name = "testdevice" },
	},
	{ .input = "{ \"device\": false }", .success = FALSE },
	{ .input = "{ \"device\": null }", .success = FALSE },

	/* msgtype */
	{ .input = "{ \"msgtype\": \"any\" }",
	  .success = TRUE,
	  .subscription = { .msgtype = WEBPUSH_SUBSCRIPTION_MSGTYPE_ANY },
	},
	{ .input = "{ \"msgtype\": \"chat\" }",
	  .success = TRUE,
	  .subscription = { .msgtype = WEBPUSH_SUBSCRIPTION_MSGTYPE_CHAT },
	},
	{ .input = "{ \"msgtype\": \"email\" }",
	  .success = TRUE,
	  .subscription = { .msgtype = WEBPUSH_SUBSCRIPTION_MSGTYPE_EMAIL },
	},
	{ .input = "{ \"msgtype\": \"\" }", .success = FALSE },
	{ .input = "{ \"msgtype\": null }", .success = FALSE },

	/* resource endpoint */
	{ .input = "{ \"resource\": { \"endpoint\": \"http://127.0.0.1/foo\" } }",
	  .success = TRUE,
	  .subscription = { .resource_endpoint = "http://127.0.0.1/foo" },
	},
	{ .input = "{ \"resource\": { \"endpoint\": null } }", .success = FALSE },

	/* other cases */
	{ .input = "{ }", .success = TRUE },
	{ .input = "{ \"foo\": \"bar\" }", .success = TRUE },

	/* resource_keys: keep this the last. The test code writes the
	   subscription here, since it doesn't seem to be possible otherwise. */
	{ .input = "{ \"resource\": { \"keys\": { \"p256dh\": \"p256dh-key\", \"auth\": \"auth-key\" } } }",
	  .success = TRUE,
	},
};

static bool
webpush_subscription_equals(const struct webpush_subscription *s1,
			    const struct webpush_subscription *s2)
{
	const struct webpush_resource_key *s1_keys, *s2_keys;
	unsigned int i, s1_count, s2_count;

	test_assert(s1->create_time == s2->create_time);
	test_assert(null_strcmp(s1->client_name, s2->client_name) == 0);
	test_assert(null_strcmp(s1->device_name, s2->device_name) == 0);
	test_assert(null_strcmp(s1->validation, s2->validation) == 0);
	test_assert(s1->msgtype == s2->msgtype);
	test_assert(null_strcmp(s1->resource_endpoint, s2->resource_endpoint) == 0);

	if (!array_is_created(&s1->resource_keys))
		test_assert(!array_is_created(&s2->resource_keys));
	else {
		s1_keys = array_get(&s1->resource_keys, &s1_count);
		s2_keys = array_get(&s2->resource_keys, &s2_count);
		test_assert(s1_count == s2_count);
		for (i = 0; i < I_MIN(s1_count, s2_count); i++) {
			test_assert_strcmp(s1_keys[i].key, s2_keys[i].key);
			test_assert_strcmp(s1_keys[i].value, s2_keys[i].value);
		}
	}

	return !test_has_failed();
}

static void test_webpush_subscription_parser(void)
{
	struct webpush_subscription subscription;
	ARRAY_TYPE(webpush_resource_key) *keys;
	struct webpush_resource_key *key;
	struct istream *input;
	const char *error;
	pool_t pool;
	bool success;

	test_begin("webpush subscription parser");

	keys = &tests[N_ELEMENTS(tests)-1].subscription.resource_keys;
	t_array_init(keys, 2);
	key = array_append_space(keys);
	key->key = "p256dh"; key->value = "p256dh-key";
	key = array_append_space(keys);
	key->key = "auth"; key->value = "auth-key";

	pool = pool_alloconly_create("webpush subscription test", 1024);
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		p_clear(pool);
		input = i_stream_create_from_data(tests[i].input, strlen(tests[i].input));
		success = webpush_subscription_parse(input, pool, &subscription, &error) == 0;
		i_stream_unref(&input);

		test_assert(tests[i].success == success);
		if (success)
			test_assert(webpush_subscription_equals(&subscription, &tests[i].subscription));
	}

	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_webpush_subscription_parser,
		NULL
	};
;
	return test_run(test_functions);
}
