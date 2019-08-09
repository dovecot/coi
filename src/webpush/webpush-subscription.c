/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "base64.h"
#include "str.h"
#include "istream.h"
#include "iso8601-date.h"
#include "json-parser.h"
#include "settings-parser.h"
#include "mail-storage-private.h"
#include "webpush-subscription.h"

#define WEBPUSH_DEFAULT_SUBSCRIPTION_EXPIRE_SECS (5*60)

#define WEBPUSH_DEVICE_KEY_MAX_LENGTH 256

static bool
webpush_subscription_is_expired(struct mailbox *box,
				const struct webpush_subscription *subscription)
{
	const char *str, *error;
	unsigned int expire_secs = WEBPUSH_DEFAULT_SUBSCRIPTION_EXPIRE_SECS;

	if (subscription->validation == NULL) {
		/* already validated */
		return FALSE;
	}

	if (ioloop_time < subscription->create_time) {
		/* time moved backwards - allow anyway.. */
		return FALSE;
	}
	str = mail_user_plugin_getenv(box->storage->user, "webpush_subscription_expire");
	if (str != NULL && settings_get_time(str, &expire_secs, &error) < 0)
		i_error("webpush: Invalid webpush_subscription_expire=%s: %s - ignoring", str, error);
	return ioloop_time - subscription->create_time >= expire_secs;
}

static bool
webpush_subscription_validate_resource_keys(const struct webpush_subscription *subscription,
					    const char **error_r)
{
	const struct webpush_resource_key *key;
	bool have_p256dh = FALSE, have_auth = FALSE;

	array_foreach(&subscription->resource_keys, key) {
		if (strcmp(key->key, "p256dh") == 0)
			have_p256dh = TRUE;
		else if (strcmp(key->key, "auth") == 0)
			have_auth = TRUE;
		else {
			*error_r = t_strdup_printf("Unknown resource key '%s'", key->key);
			return FALSE;
		}
	}
	if (!have_p256dh) {
		*error_r = "resource { key { p256dh } } is missing";
		return FALSE;
	}
	if (!have_auth) {
		*error_r = "resource { key { auth } } is missing";
		return FALSE;
	}
	return TRUE;
}

static bool
webpush_subscription_validate(const struct webpush_subscription *subscription,
			      const char **error_r)
{
	const char *missing = NULL;

	/* make sure everything exists */
	if (subscription->client_name == NULL)
		missing = "client";
	else if (subscription->device_name == NULL)
		missing = "device";
	else if (subscription->msgtype == WEBPUSH_SUBSCRIPTION_MSGTYPE_UNKNOWN)
		missing = "msgtype";
	else if (subscription->resource_endpoint == NULL)
		missing = "resource { endpoint }";
	else if (!array_is_created(&subscription->resource_keys))
		missing = "resource { keys }";

	if (missing != NULL) {
		*error_r = t_strdup_printf("%s is missing", missing);
		return FALSE;
	}
	if (!webpush_subscription_validate_resource_keys(subscription, error_r))
		return FALSE;
	return TRUE;
}

static void webpush_json_append_comma_if_needed(string_t *str)
{
	i_assert(str_len(str) > 0);
	switch (str_data(str)[str_len(str)-1]) {
	case '{':
	case ',':
		break;
	default:
		str_append_c(str, ',');
		break;
	}
}

static void
webpush_append_keyvalue(string_t *str, const char *key, const char *value)
{
	if (value == NULL)
		return;

	webpush_json_append_comma_if_needed(str);
	str_append_c(str, '"');
	json_append_escaped(str, key);
	str_append(str, "\":\"");
	json_append_escaped(str, value);
	str_append_c(str, '"');
}

static const char *
webpush_subscription_to_string(const struct webpush_subscription *subscription,
			       bool internal)
{
	string_t *str = t_str_new(128);

	str_append_c(str, '{');
	str_printfa(str, "\"create_time\":\"%s\"",
		    iso8601_date_create(subscription->create_time));
	if (internal) {
		webpush_append_keyvalue(str, "validation",
					subscription->validation);
	} else {
		str_printfa(str, ",\"validated\":%s",
			    subscription->validation == NULL ? "true" : "false");
	}
	webpush_append_keyvalue(str, "client", subscription->client_name);
	webpush_append_keyvalue(str, "device", subscription->device_name);
	if (subscription->msgtype != WEBPUSH_SUBSCRIPTION_MSGTYPE_UNKNOWN) {
		webpush_append_keyvalue(str, "msgtype",
			webpush_subscription_msgtype_to_string(subscription->msgtype));
	}

	webpush_json_append_comma_if_needed(str);
	str_append(str, "\"resource\":{");
	webpush_append_keyvalue(str, "endpoint", subscription->resource_endpoint);
	if (array_is_created(&subscription->resource_keys) > 0) {
		const struct webpush_resource_key *key;

		webpush_json_append_comma_if_needed(str);
		str_append(str, "\"keys\":{");
		array_foreach(&subscription->resource_keys, key)
			webpush_append_keyvalue(str, key->key, key->value);
		str_append_c(str, '}');
	}
	str_append(str, "}}");
	return str_c(str);
}

static int
webpush_subscription_parse_value(const struct mail_attribute_value *value,
				 pool_t pool,
				 struct webpush_subscription *subscription_r,
				 const char **error_r)
{
	int ret;

	if (value->value_stream != NULL) {
		ret = webpush_subscription_parse(value->value_stream, pool,
						 subscription_r, error_r);
	} else {
		struct istream *input =
			i_stream_create_from_data(value->value, strlen(value->value));
		ret = webpush_subscription_parse(input, pool,
						 subscription_r, error_r);
		i_stream_unref(&input);
	}
	if (ret < 0) {
		/* make sure we don't read partial subscription */
		i_zero(subscription_r);
	}
	return ret;
}

static void
webpush_subscription_delete(struct mailbox *box, const char *storage_key)
{
	struct mailbox_transaction_context *t;

	if (mailbox_open(box) < 0) {
		i_error("webpush: Failed to unset delete subscription %s: "
			"Mailbox couldn't be opened: %s",
			storage_key, mailbox_get_last_internal_error(box, NULL));
		return;
	}

	t = mailbox_transaction_begin(box, 0, "webpush subscription delete");
	mailbox_attribute_unset(t, MAIL_ATTRIBUTE_TYPE_PRIVATE, storage_key);
	if (mailbox_transaction_commit(&t) < 0) {
		i_error("webpush: Failed to unset delete subscription %s: %s",
			storage_key, mailbox_get_last_internal_error(box, NULL));
	}
}

int webpush_subscription_read(struct mailbox *box, const char *device_key,
			      pool_t pool,
			      struct webpush_subscription *subscription_r)
{
	struct mail_attribute_value value;
	const char *storage_key, *error;
	int ret;

	storage_key = t_strconcat(MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX,
				  device_key, NULL);

	i_zero(subscription_r);
	ret = mailbox_attribute_get_stream(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
					   storage_key, &value);
	if (ret <= 0)
		return ret;

	if (webpush_subscription_parse_value(&value, pool, subscription_r, &error) < 0 ||
	    !webpush_subscription_validate(subscription_r, &error)) {
		i_error("webpush: Invalid subscription %s - deleting: %s",
			device_key, error);
		webpush_subscription_delete(box, storage_key);
		return 0;
	}
	if (webpush_subscription_is_expired(box, subscription_r)) {
		/* already expired - delete silently */
		webpush_subscription_delete(box, storage_key);
		return 0;
	}
	return 1;
}

static int
webpush_subscription_attribute_get(struct mailbox *box, const char *key,
				   struct mail_attribute_value *value_r)
{
	struct webpush_subscription subscription;
	const char *device_key;
	int ret;

	i_assert(str_begins(key, MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX));
	device_key = key + strlen(MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX);

	ret = webpush_subscription_read(box, device_key,
					pool_datastack_create(), &subscription);
	if (ret <= 0)
		return ret;

	value_r->value = webpush_subscription_to_string(&subscription, FALSE);
	return 1;
}

static int
webpush_subscription_store(struct mailbox_transaction_context *t,
			   const char *device_key,
			   const struct webpush_subscription *subscription)
{
	struct mail_attribute_value storage_value;
	const char *storage_key;

	storage_key = t_strconcat(MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX,
				  device_key, NULL);
	i_zero(&storage_value);
	storage_value.value = webpush_subscription_to_string(subscription, TRUE);
	if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				  storage_key, &storage_value) < 0) {
		i_error("webpush: Can't store subscription: %s", 
			mail_storage_get_last_internal_error(t->box->storage, NULL));
		return -1;
	}
	return 0;
}

static int
webpush_subscription_validation_set(struct mailbox_transaction_context *t,
				    const char *device_key,
				    const struct mail_attribute_value *value)
{
	struct webpush_subscription old_subscription;
	const char *validation;
	int ret;

	if (mailbox_attribute_value_to_string(t->box->storage, value, &validation) < 0)
		return -1;
	if (validation == NULL) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
				       "Can't unset validation key");
		return -1;
	}

	/* Finishing the registration. Verify that the given validation string
	   is the same one that is currently stored. */
	ret = webpush_subscription_read(t->box, device_key,
					pool_datastack_create(),
					&old_subscription);
	if (ret < 0)
		return -1;

	if (ret == 0 || old_subscription.validation == NULL ||
	    strcmp(old_subscription.validation, validation) != 0) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
			"Subscription with matching validation not found");
		return -1;
	}
	/* Finish registration by removing validation from the old stored
	   subscription. We'll ignore everything else in the new
	   subscription. */
	old_subscription.validation = NULL;
	return webpush_subscription_store(t, device_key, &old_subscription);
}

static int
webpush_subscription_attribute_set(struct mailbox_transaction_context *t,
				   const char *key,
				   const struct mail_attribute_value *value)
{
	struct webpush_subscription subscription;
	const char *p, *device_key, *storage_key, *error;

	i_assert(str_begins(key, MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX));
	device_key = key + strlen(MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX);
	storage_key = t_strconcat(MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX,
				  device_key, NULL);

	p = strchr(device_key, '/');
	if (p != NULL) {
		if (strcmp(p, "/validation") == 0) {
			device_key = t_strdup_until(device_key, p);
			return webpush_subscription_validation_set(t, device_key, value);
		}
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
				       "Device key must not contain '/'");
		return -1;
	}
	if (strlen(device_key) > WEBPUSH_DEVICE_KEY_MAX_LENGTH) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
				       "Device key is too long");
		return -1;
	}

	if (value->value == NULL && value->value_stream == NULL) {
		/* remove the value */
		if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
					  storage_key, value) < 0) {
			i_error("webpush: Can't remove subscription: %s",
				mail_storage_get_last_internal_error(t->box->storage, NULL));
			return -1;
		}
		return 0;
	}

	/* parse the JSON value into a struct */
	if (webpush_subscription_parse_value(value, pool_datastack_create(),
					     &subscription, &error) < 0) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
			t_strdup_printf("Invalid JSON: %s", error));
		return -1;
	}

	/* Starting device subscription. Generate a new unique
	   validation string and send it as a push notification. */
	unsigned char buf[32];
	string_t *str = t_str_new(64);

	if (!webpush_subscription_validate(&subscription, &error)) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
				       t_strdup_printf("Invalid subscription: %s", error));
		return -1;
	}

	random_fill(buf, sizeof(buf));
	base64_encode(buf, sizeof(buf), str);
	subscription.validation = str_c(str);
	subscription.create_time = ioloop_time;
	//FIXME: send push notification

	return webpush_subscription_store(t, device_key, &subscription);
}

static int
webpush_subscription_attribute_iter(struct mailbox *box, const char *key_prefix,
				    pool_t pool, ARRAY_TYPE(const_string) *keys)
{
	struct mailbox_attribute_iter *iter;
	const char *key;

	iter = mailbox_attribute_iter_init(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
		MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX);
	while ((key = mailbox_attribute_iter_next(iter)) != NULL) {
		if (str_begins(key, key_prefix)) {
			key = p_strdup(pool, key);
			array_push_back(keys, &key);
		}
	}
	return mailbox_attribute_iter_deinit(&iter);
}

static const struct mailbox_attribute_internal
iattr_webpush_device = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN |
		MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.get = webpush_subscription_attribute_get,
	.set = webpush_subscription_attribute_set,
	.iter = webpush_subscription_attribute_iter,
};

void webpush_device_init(void)
{
	mailbox_attribute_register_internal(&iattr_webpush_device);
}
