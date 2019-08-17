#ifndef WEBPUSH_SUBSCRIPTION_H
#define WEBPUSH_SUBSCRIPTION_H

struct mailbox;
struct mail_user;

#include "webpush-plugin.h"

#define MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_SUBSCRIPTION_PREFIX \
	MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_PREFIX"subscription/"

#define MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX \
	MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_PREFIX"subscription/"

#define WEBPUSH_DEFAULT_SUBSCRIPTION_LIMIT 10

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
	const char *device_key; /* from the metadata key */
	const char *validation;

	const char *client_name;
	const char *device_name;
	enum webpush_subscription_msgtype msgtype;

	const char *resource_endpoint;
	ARRAY_TYPE(webpush_resource_key) resource_keys;

	/* generated: */
	struct http_url *resource_endpoint_http_url;
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

/* Read all subscriptions into the given array. Returns 0 on success,
   -1 on internal error. If validated_only=TRUE, it returns only subscriptions
   whose endpoints have successfully been validated already. Expired
   non-validated subscriptions are automatically deleted. */
int webpush_subscriptions_read(struct mailbox *box, pool_t pool,
			       bool validated_only,
			       ARRAY_TYPE(webpush_subscription) *subscriptions);

/* Returns the maximum number of allowed subscriptions. */
unsigned int webpush_subscription_get_limit(struct mail_user *user);

int webpush_subscription_parse(struct istream *input, pool_t pool,
			       struct webpush_subscription *subscription_r,
			       const char **error_r);

const char *webpush_subscription_msgtype_to_string(enum webpush_subscription_msgtype msgtype);

#endif
