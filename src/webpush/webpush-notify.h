#ifndef WEBPUSH_NOTIFY_H
#define WEBPUSH_NOTIFY_H

#include "module-context.h"
#include "mail-user.h"
#include "webpush-subscription.h"

#define WEBPUSH_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, webpush_mail_user_module)

struct webpush_notify_cache {
	pool_t pool;
	time_t expire_time;
	ARRAY_TYPE(webpush_subscription) subscriptions;
};

struct webpush_notify_config {
	struct event *event;
	unsigned int cache_lifetime_secs;
	unsigned int http_max_retries;
	unsigned int http_timeout_msecs;
	char *http_rawlog_dir;

	struct webpush_notify_cache cache;
};

struct webpush_mail_user {
	union mail_user_module_context module_ctx;
	struct webpush_notify_config *dconfig;
};

extern MODULE_CONTEXT_DEFINE(webpush_mail_user_module,
			     &mail_user_module_register);

#endif
