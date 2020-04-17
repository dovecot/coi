/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "istream.h"
#include "iso8601-date.h"
#include "json-parser.h"
#include "http-url.h"
#include "webpush-subscription.h"

#define WEBPUSH_VALUE_MAX_LENGTH 1024
#define WEBPUSH_MAX_KEYS_COUNT 2
#define WEBPUSH_MAX_EXCLUDE_FROM_COUNT 10

static const char *webpush_subscription_msgtype_strings[] = {
	[WEBPUSH_SUBSCRIPTION_MSGTYPE_ANY] = "any",
	[WEBPUSH_SUBSCRIPTION_MSGTYPE_CHAT] = "chat",
	[WEBPUSH_SUBSCRIPTION_MSGTYPE_EMAIL] = "email",
};

const char *webpush_subscription_msgtype_to_string(enum webpush_subscription_msgtype msgtype)
{
	return webpush_subscription_msgtype_strings[msgtype];
}

static bool
webpush_subscription_msgtype_parse(const char *value,
				   enum webpush_subscription_msgtype *msgtype_r)
{
	enum webpush_subscription_msgtype msgtype;

	for (msgtype = WEBPUSH_SUBSCRIPTION_MSGTYPE_ANY;
	     msgtype <= WEBPUSH_SUBSCRIPTION_MSGTYPE_EMAIL;
	     msgtype++) {
		if (strcmp(webpush_subscription_msgtype_strings[msgtype], value) == 0) {
			*msgtype_r = msgtype;
			return TRUE;
		}
	}
	return FALSE;
}

static bool
webpush_subscription_get_string(const char *value_in, pool_t pool,
				const char **value_out_r, const char **error_r)
{
	if (strlen(value_in) > WEBPUSH_VALUE_MAX_LENGTH) {
		*error_r = "Value too long";
		return FALSE;
	}
	*value_out_r = p_strdup(pool, value_in);
	return TRUE;
}

static bool
webpush_subscription_endpoint_parse(struct webpush_subscription *subscription,
				    pool_t pool, const char **error_r)
{
	const char *error;

	if (http_url_parse(subscription->resource_endpoint, NULL,
			   HTTP_URL_ALLOW_USERINFO_PART, pool,
			   &subscription->resource_endpoint_http_url,
			   &error) < 0) {
		*error_r = t_strdup_printf("Invalid resource endpoint URL %s: %s",
					   subscription->resource_endpoint, error);
		return FALSE;
	}
	return TRUE;
}

static bool
webpush_subscription_parse_keys(struct json_parser *parser, pool_t pool,
				struct webpush_subscription *subscription_r,
				const char **error_r)
{
	const char *key, *value;
	enum json_type type;

	if (json_parse_next(parser, &type, &key) <= 0 ||
	    type != JSON_TYPE_OBJECT) {
		*error_r = "keys: Expected object";
		return FALSE;
	}

	if (!array_is_created(&subscription_r->resource_keys))
		p_array_init(&subscription_r->resource_keys, pool, 2);
	while (json_parse_next(parser, &type, &key) > 0) {
		if (type == JSON_TYPE_OBJECT_END)
			return TRUE;
		if (type != JSON_TYPE_OBJECT_KEY) {
			*error_r = "keys: Expected object-key";
			return FALSE;
		}
		if (array_count(&subscription_r->resource_keys) >= WEBPUSH_MAX_KEYS_COUNT) {
			*error_r = "keys: Too many keys";
			return FALSE;
		}

		if (!webpush_subscription_get_string(key, pool, &key, error_r))
			return FALSE;

		if (json_parse_next(parser, &type, &value) <= 0 ||
		    type != JSON_TYPE_STRING) {
			*error_r = "keys: Expected string";
			return FALSE;
		}
		struct webpush_resource_key *res_key =
			array_append_space(&subscription_r->resource_keys);
		res_key->key = key;
		if (!webpush_subscription_get_string(value, pool, &res_key->value, error_r))
			return FALSE;
	}
	*error_r = "keys: Expected object-end";
	return FALSE;
}

static bool
webpush_subscription_parse_resource(struct json_parser *parser, pool_t pool,
				    struct webpush_subscription *subscription_r,
				    const char **error_r)
{
	const char *key, *value;
	enum json_type type;

	if (json_parse_next(parser, &type, &key) <= 0 ||
	    type != JSON_TYPE_OBJECT) {
		*error_r = "resource: Expected object";
		return FALSE;
	}

	while (json_parse_next(parser, &type, &key) > 0) {
		if (type == JSON_TYPE_OBJECT_END)
			return TRUE;
		if (type != JSON_TYPE_OBJECT_KEY) {
			*error_r = "resource: Expected object-key";
			return FALSE;
		}
		if (strcmp(key, "endpoint") == 0) {
			if (json_parse_next(parser, &type, &value) <= 0 ||
			    type != JSON_TYPE_STRING) {
				*error_r = "endpoint: Expected string";
				return FALSE;
			}
			if (!webpush_subscription_get_string(value, pool,
					&subscription_r->resource_endpoint, error_r))
				return FALSE;
			if (!webpush_subscription_endpoint_parse(subscription_r,
								 pool, error_r))
				return FALSE;
		} else if (strcmp(key, "keys") == 0) {
			if (!webpush_subscription_parse_keys(parser, pool, subscription_r, error_r))
				return FALSE;
		} else {
			json_parse_skip_next(parser);
		}
	}
	*error_r = "resource: Expected object-end";
	return FALSE;
}

static bool
webpush_subscription_parse_exclude_from(struct json_parser *parser, pool_t pool,
					struct webpush_subscription *subscription_r,
					const char **error_r)
{
	ARRAY_TYPE(const_string) addresses;
	const char *key, *value;
	enum json_type type;

	if (json_parse_next(parser, &type, &key) <= 0 ||
	    type != JSON_TYPE_ARRAY) {
		*error_r = "exclude_from: Expected array";
		return FALSE;
	}

	p_array_init(&addresses, pool, 2);
	while (json_parse_next(parser, &type, &value) > 0) {
		if (type == JSON_TYPE_ARRAY_END) {
			subscription_r->excluded_from_addr =
				array_get(&addresses, &subscription_r->excluded_from_addr_count);
			return TRUE;
		}
		if (type != JSON_TYPE_STRING) {
			*error_r = "exclude_from: Expected string";
			return FALSE;
		}
		if (array_count(&addresses) >= WEBPUSH_MAX_EXCLUDE_FROM_COUNT) {
			*error_r = "exclude_from: Too many excluded from addresses";
			return FALSE;
		}
		if (!webpush_subscription_get_string(value, pool, &value, error_r))
			return FALSE;
		array_push_back(&addresses, &value);
	}
	*error_r = "exclude_from: Expected array-end";
	return FALSE;
}

static bool
webpush_subscription_parse_root(struct json_parser *parser, pool_t pool,
				struct webpush_subscription *subscription_r,
				const char **error_r)
{
	const char *key, *value;
	enum json_type type;
	int tz;

	while (json_parse_next(parser, &type, &key) > 0) {
		if (type != JSON_TYPE_OBJECT_KEY) {
			*error_r = "Expected object-key";
			return FALSE;
		}

		const char **value_p = NULL;
		enum {
			PARSE_STRP,
			PARSE_MSGTYPE,
			PARSE_CREATE_TIME,
		} parse_type = PARSE_STRP;
		if (strcmp(key, "client") == 0)
			value_p = &subscription_r->client_name;
		else if (strcmp(key, "device") == 0)
			value_p = &subscription_r->device_name;
		else if (strcmp(key, "msgtype") == 0)
			parse_type = PARSE_MSGTYPE;
		else if (strcmp(key, "validation") == 0)
			value_p = &subscription_r->validation;
		else if (strcmp(key, "created") == 0)
			parse_type = PARSE_CREATE_TIME;
		else if (strcmp(key, "resource") == 0) {
			if (!webpush_subscription_parse_resource(parser, pool, subscription_r, error_r))
				return FALSE;
			continue;
		} else if (strcmp(key, "exclude_from") == 0) {
			if (!webpush_subscription_parse_exclude_from(parser, pool, subscription_r, error_r))
				return FALSE;
			continue;
		} else {
			/* unknown key */
			json_parse_skip_next(parser);
			continue;
		}
		if (json_parse_next(parser, &type, &value) <= 0 ||
		    type != JSON_TYPE_STRING) {
			*error_r = "Expected string";
			return FALSE;
		}
		switch (parse_type) {
		case PARSE_STRP:
			if (!webpush_subscription_get_string(value, pool, value_p, error_r))
				return FALSE;
			break;
		case PARSE_MSGTYPE:
			if (!webpush_subscription_msgtype_parse(value, &subscription_r->msgtype)) {
				*error_r = "Unknown msgtype";
				return FALSE;
			}
			break;
		case PARSE_CREATE_TIME:
			if (!iso8601_date_parse((const unsigned char *)value,
						strlen(value),
						&subscription_r->create_time,
						&tz)) {
				*error_r = "created: Invalid value";
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}

int webpush_subscription_parse(struct istream *input, pool_t pool,
			       struct webpush_subscription *subscription_r,
			       const char **error_r)
{
	struct json_parser *parser;
	const char *error;

	i_assert(input->blocking);

	i_zero(subscription_r);
	parser = json_parser_init(input);

	/* parse root */
	if (!webpush_subscription_parse_root(parser, pool, subscription_r, error_r)) {
		(void)json_parser_deinit(&parser, &error);
		return -1;
	}

	if (json_parser_deinit(&parser, error_r) < 0)
		return -1;
	return 0;
}

int webpush_subscription_extract_aesgcm_keys(const struct webpush_subscription *subscription,
					     buffer_t *auth_r, buffer_t *p256dh_r,
					     const char **error_r)
{
	const struct webpush_resource_key *key;
	bool have_auth = FALSE;
	bool have_p256dh = FALSE;
	i_assert(array_is_created(&subscription->resource_keys));

	array_foreach(&subscription->resource_keys, key) {
		if (strcmp(key->key, "auth") == 0) {
			if (base64url_decode(BASE64_DECODE_FLAG_IGNORE_PADDING,
					     key->value, strlen(key->value),
					     auth_r) != 0) {
				*error_r = "Invalid base64 encoded 'auth'";
				return -1;
			}
			have_auth = TRUE;
		} else if (strcmp(key->key, "p256dh") == 0) {
			if (base64url_decode(BASE64_DECODE_FLAG_IGNORE_PADDING,
					     key->value, strlen(key->value),
					     p256dh_r) != 0) {
				*error_r = "Invalid base64 encoded 'p256dh'";
				return -1;
			}
			have_p256dh = TRUE;
		}
	}

	if (!have_auth) {
		*error_r = "Missing 'auth' in subscription";
		return -1;
	} else if (!have_p256dh) {
		*error_r = "Missing 'p256dh' in subscription";
		return -1;
	}

	return 0;
}
