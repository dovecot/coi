#ifndef WEBPUSH_SUBSCRIPTION_H
#define WEBPUSH_SUBSCRIPTION_H

struct mailbox;

#include "webpush-plugin.h"

#define MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX \
	MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_PREFIX"subscription/"

#define MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX \
	MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_PREFIX"subscription/"

enum webpush_subscription_msgtype {
	WEBPUSH_SUBSCRIPTION_MSGTYPE_UNKNOWN = 0,
	WEBPUSH_SUBSCRIPTION_MSGTYPE_ANY,
	WEBPUSH_SUBSCRIPTION_MSGTYPE_CHAT,
	WEBPUSH_SUBSCRIPTION_MSGTYPE_EMAIL,
};

struct webpush_resource_key {
	const char *key, *value;
};
ARRAY_DEFINE_TYPE(webpush_resource_key, struct webpush_resource_key);

struct webpush_subscription {
	time_t create_time;
	const char *validation;

	const char *client_name;
	const char *device_name;
	enum webpush_subscription_msgtype msgtype;

	const char *resource_endpoint;
	ARRAY_TYPE(webpush_resource_key) resource_keys;
};
ARRAY_DEFINE_TYPE(webpush_subscription, struct webpush_subscription);

/* Lookup a subscription from mailbox attributes and parse it. The device_key
   contains only the unique device ID, i.e. it doesn't include the
   MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX.

   Returns 1 if ok, 0 if device_key doesn't exist, -1 on internal error.
   Corrupted subscriptions return 0 and they are immediately deleted. */
int webpush_subscription_read(struct mailbox *box, const char *device_key,
			      pool_t pool,
			      struct webpush_subscription *subscription_r);

int webpush_subscription_parse(struct istream *input, pool_t pool,
			       struct webpush_subscription *subscription_r,
			       const char **error_r);

const char *webpush_subscription_msgtype_to_string(enum webpush_subscription_msgtype msgtype);

#endif
