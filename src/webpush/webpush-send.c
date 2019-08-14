/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "http-client.h"
#include "http-url.h"
#include "iostream-ssl.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "webpush-subscription.h"
#include "webpush-notify.h"
#include "webpush-message.h"
#include "webpush-send.h"

#define WEBPUSH_ERROR_RETRY_MSECS 1000

struct webpush_send_context {
	struct mail_user *user;
	struct event *event;
	char *device_key;
	struct http_client_request *request;
};

struct webpush_notify_global *webpush_global = NULL;

static void
webpush_send_global_init(struct mail_user *user,
			 struct webpush_notify_config *config)
{
	struct http_client_settings http_set;
	struct ssl_iostream_settings ssl_set;

	if (webpush_global->http_client != NULL)
		return;

	/* this is going to use the first user's settings, but these are
	   unlikely to change between users so it shouldn't matter much. */
	i_zero(&http_set);
	http_set.debug = user->mail_debug;
	http_set.rawlog_dir = config->http_rawlog_dir;
	http_set.max_attempts = config->http_max_retries+1;
	http_set.request_timeout_msecs = config->http_timeout_msecs;
	http_set.event_parent = user->event;
	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(user, &ssl_set);
	http_set.ssl = &ssl_set;

	webpush_global->http_client = http_client_init(&http_set);
}

static void
webpush_notify_delete_subscription(struct mail_user *user,
				   const char *device_key)
{
	const char *storage_key =
		t_strconcat(MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_SUBSCRIPTION_PREFIX,
			    device_key, NULL);
	struct mail_namespace *ns =
		mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX", 0);
	(void)webpush_subscription_delete(box, storage_key);
	mailbox_free(&box);
}

static int webpush_response_try_retry(struct webpush_send_context *ctx,
				      const struct http_response *response)
{
	if (response->status != 429 && response->status/100 != 5)
		return -1;

	if (http_client_request_delay_from_response(ctx->request, response) <= 0)
		http_client_request_delay_msecs(ctx->request, WEBPUSH_ERROR_RETRY_MSECS);
	return http_client_request_try_retry(ctx->request) ? 1 : 0;
}

static void
webpush_notify_http_callback(const struct http_response *response,
			     struct webpush_send_context *ctx)
{
	const char *error;
	int ret;

	/* Use only e_debug() for all logging, because these are untrusted
	   endpoints. Normally admins shouldn't need to see anything about
	   them. */
	switch (response->status) {
	case 201:
		e_debug(ctx->event, "Notification sent successfully: %s",
			http_response_get_message(response));
		break;
	case 404:
	case 410:
		e_debug(ctx->event, "Subscription is no longer valid: %s",
			http_response_get_message(response));
		webpush_notify_delete_subscription(ctx->user, ctx->device_key);
		break;
	case 429: /* Too many requests */
	default:
		error = t_strdup_printf("Error when sending notification: POST %s failed: %s",
				http_client_request_get_target(ctx->request),
				http_response_get_message(response));
		if ((ret = webpush_response_try_retry(ctx, response)) > 0)
			e_debug(ctx->event, "%s - retrying", error);
		else
			e_debug(ctx->event, "%s", error);
		if (ret < 0) {
			/* Not a temporary error - disable subscription */
			webpush_notify_delete_subscription(ctx->user, ctx->device_key);
		}
		break;
	}
	event_unref(&ctx->event);
	i_free(ctx->device_key);
	i_free(ctx);
}

bool webpush_send(struct mail_user *user,
		  const struct webpush_subscription *subscription,
		  string_t *msg, const char **error_r)
{
	struct webpush_mail_user *wuser = WEBPUSH_USER_CONTEXT(user);
	struct webpush_notify_config *dconfig = wuser->dconfig;
	struct istream *payload;
	struct webpush_send_context *ctx;

	i_assert(subscription->device_key != NULL);

	if (dconfig == NULL) {
		*error_r = "Webpush not enabled";
		return FALSE;
	}
	webpush_send_global_init(user, dconfig);

	ctx = i_new(struct webpush_send_context, 1);
	ctx->user = user;
	ctx->event = event_create(dconfig->event);
	ctx->device_key = i_strdup(subscription->device_key);
	event_set_append_log_prefix(ctx->event,
		t_strdup_printf("%s: ", subscription->device_key));

	ctx->request = http_client_request_url(webpush_global->http_client, "POST",
		subscription->resource_endpoint_http_url,
		webpush_notify_http_callback, ctx);
	http_client_request_set_event(ctx->request, dconfig->event);
	http_client_request_add_header(ctx->request, "Content-Type",
				       "application/json; charset=utf-8");

	e_debug(dconfig->event, "Sending notification: %s", str_c(msg));

	/* FIXME: encrypt the string */

	payload = i_stream_create_copy_from_string(msg);
	http_client_request_set_payload(ctx->request, payload, FALSE);

	http_client_request_submit(ctx->request);
	i_stream_unref(&payload);
	return TRUE;
}
