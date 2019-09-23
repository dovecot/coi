/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "str-sanitize.h"
#include "http-client.h"
#include "http-url.h"
#include "iostream-ssl.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "json-parser.h"
#include "webpush-subscription.h"
#include "webpush-notify.h"
#include "webpush-payload.h"
#include "webpush-message.h"
#include "webpush-send.h"

#define WEBPUSH_TTL_SECS 30 //FIXME: configurable?
#define WEBPUSH_ERROR_RETRY_MSECS 1000

struct webpush_send_context {
	struct mail_user *user;
	struct event *event;
	char *device_key;
	struct http_client_request *request;

	char *response_error;
	unsigned int response_status;
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

static bool
webpush_notify_http_callback(const struct http_response *response,
			     struct webpush_send_context *ctx,
			     bool *retrying_r)
{
	int ret;

	ctx->response_status = response->status;
	*retrying_r = FALSE;

	/* Use only e_debug() for all logging, because these are untrusted
	   endpoints. Normally admins shouldn't need to see anything about
	   them. */
	switch (response->status) {
	case 201:
		e_debug(ctx->event, "Notification sent successfully: %s",
			http_response_get_message(response));
		return TRUE;
	case 404:
	case 410:
		ctx->response_error = i_strdup_printf(
			"Subscription is no longer valid: %s",
			http_response_get_message(response));
		e_debug(ctx->event, "%s", ctx->response_error);
		return FALSE;
	case 429: /* Too many requests */
	default:
		ctx->response_error = i_strdup_printf(
			"Error when sending notification: POST %s failed: %s",
			http_client_request_get_target(ctx->request),
			http_response_get_message(response));
		if ((ret = webpush_response_try_retry(ctx, response)) > 0) {
			*retrying_r = TRUE;
			e_debug(ctx->event, "%s - retrying", ctx->response_error);
		} else
			e_debug(ctx->event, "%s", ctx->response_error);
		if (ret < 0) {
			/* Not a temporary error - disable subscription */
			return FALSE;
		}
		return TRUE;
	}
	i_unreached();
}

static void webpush_send_context_free(struct webpush_send_context *ctx)
{
	event_unref(&ctx->event);
	i_free(ctx->response_error);
	i_free(ctx->device_key);
	i_free(ctx);
}

static void
webpush_notify_async_http_callback(const struct http_response *response,
				   struct webpush_send_context *ctx)
{
	bool retrying;

	if (!webpush_notify_http_callback(response, ctx, &retrying))
		webpush_notify_delete_subscription(ctx->user, ctx->device_key);
	if (!retrying)
		webpush_send_context_free(ctx);
}

static void
webpush_notify_sync_http_callback(const struct http_response *response,
				  struct webpush_send_context *ctx)
{
	bool retrying;

	(void)webpush_notify_http_callback(response, ctx, &retrying);
}

bool webpush_send(struct mail_user *user,
		  const struct webpush_subscription *subscription,
		  struct dcrypt_private_key *vapid_key,
		  string_t *msg, bool async, const char **error_r)
{
	struct webpush_mail_user *wuser = WEBPUSH_USER_CONTEXT(user);
	struct webpush_notify_config *dconfig;
	struct istream *payload;
	struct webpush_send_context *ctx;
	const char *error;
	bool success;

	i_assert(subscription->device_key != NULL);

	if (wuser == NULL) {
		*error_r = "Webpush not enabled";
		return FALSE;
	}
	dconfig = wuser->dconfig;
	webpush_send_global_init(user, dconfig);

	/* encrypt the msg */
	buffer_t *ephemeral_key = t_buffer_create(65);
	buffer_t *salt = t_buffer_create(16);
	uint16_t padding = (1024 - (str_len(msg) % 1024)) % 1024;
	if (padding > WEBPUSH_MSG_MAX_PLAINTEXT_LEN - str_len(msg))
		padding = WEBPUSH_MSG_MAX_PLAINTEXT_LEN - str_len(msg);

	size_t encrypted_msg_max_size = str_len(msg) + padding + 16 + 8;
	buffer_t *encrypted_msg =
		buffer_create_dynamic(default_pool, encrypted_msg_max_size);
	if (webpush_payload_encrypt(subscription,
				    PAYLOAD_ENCRYPTION_TYPE_AES128GCM,
				    msg, padding, ephemeral_key, salt,
				    encrypted_msg, &error) < 0) {
		e_debug(dconfig->event, "Failed to encrypt payload: %s", error);
		webpush_notify_delete_subscription(user, subscription->device_key);
		buffer_free(&encrypted_msg);
		*error_r = "Failed to encrypt payload";
		return FALSE;
	}
	/* make sure the buffer sizes were chosen well */
	i_assert(buffer_get_writable_size(ephemeral_key) == 65);
	i_assert(buffer_get_writable_size(salt) == 16);
	i_assert(buffer_get_writable_size(encrypted_msg) == encrypted_msg_max_size);

	size_t encrypted_full_max_size =
		salt->used + 4 + 1 + ephemeral_key->used + encrypted_msg->used;
	buffer_t *encrypted_full =
		buffer_create_dynamic(default_pool, encrypted_full_max_size);
	/* "rs" must be greater than the full payload */
	uint32_t record_len = cpu32_to_be(WEBPUSH_MSG_MAX_ENCRYPTED_SIZE+1);
	buffer_append(encrypted_full, salt->data, salt->used);
	buffer_append(encrypted_full, &record_len, sizeof(record_len));
	buffer_append_c(encrypted_full, ephemeral_key->used);
	buffer_append(encrypted_full, ephemeral_key->data, ephemeral_key->used);
	buffer_append(encrypted_full, encrypted_msg->data, encrypted_msg->used);
	i_assert(buffer_get_writable_size(encrypted_full) == encrypted_full_max_size);
	buffer_free(&encrypted_msg);

	/* create JWT header, which signs the encrypted_full with
	   the VAPID key */
	string_t *b64_token = t_str_new(128);
	string_t *b64_key = t_str_new(128);
	string_t *jwt_body = t_str_new(128);
	str_append(jwt_body, "{\"aud\":\"");
	if (!subscription->resource_endpoint_http_url->have_ssl)
		uri_append_scheme(jwt_body, "http");
	else
		uri_append_scheme(jwt_body, "https");
	str_append(jwt_body, "//");
	uri_append_host(jwt_body, &subscription->resource_endpoint_http_url->host);
	str_printfa(jwt_body, "\",\"iat\":%"PRIdTIME_T",\"exp\":%"PRIdTIME_T"}",
		    ioloop_time, ioloop_time + WEBPUSH_TTL_SECS);
	if (webpush_payload_sign(jwt_body, vapid_key,
				 b64_token, b64_key, &error) < 0) {
		e_debug(dconfig->event, "Failed to sign payload: %s", error);
		webpush_notify_delete_subscription(user, subscription->device_key);
		buffer_free(&encrypted_full);
		*error_r = "Failed to sign payload";
		return FALSE;
	}

	ctx = i_new(struct webpush_send_context, 1);
	ctx->user = user;
	ctx->event = event_create(dconfig->event);
	ctx->device_key = i_strdup(subscription->device_key);
	event_set_append_log_prefix(ctx->event,
		t_strdup_printf("%s: ", subscription->device_key));

	if (async) {
		ctx->request = http_client_request_url(webpush_global->http_client, "POST",
			subscription->resource_endpoint_http_url,
			webpush_notify_async_http_callback, ctx);
	} else {
		ctx->request = http_client_request_url(webpush_global->http_client, "POST",
			subscription->resource_endpoint_http_url,
			webpush_notify_sync_http_callback, ctx);
	}
	http_client_request_set_event(ctx->request, dconfig->event);
	http_client_request_add_header(ctx->request, "TTL", dec2str(WEBPUSH_TTL_SECS));
	http_client_request_add_header(ctx->request, "Content-Encoding", "aes128gcm");
	http_client_request_add_header(ctx->request, "Authorization",
		t_strdup_printf("vapid t=%s, k=%s", str_c(b64_token), str_c(b64_key)));

	e_debug(dconfig->event, "Sending notification: %s", str_c(msg));

	i_assert(encrypted_full->used <= WEBPUSH_MSG_MAX_ENCRYPTED_SIZE);
	payload = i_stream_create_copy_from_string(encrypted_full);
	http_client_request_set_payload(ctx->request, payload, FALSE);

	http_client_request_submit(ctx->request);
	i_stream_unref(&payload);
	buffer_free(&encrypted_full);

	if (!async) {
		http_client_wait(webpush_global->http_client);
		/* Return success only when the push notification went
		   successfully through. This also means that if the push
		   service has temporary problems it will result in a client
		   visible error. */
		success = ctx->response_status == 201;
		if (!success) {
			/* Give client access to the exact HTTP response.
			   It can help debugging problems, and these shouldn't
			   have any sensitive information. */
			*error_r = str_sanitize(t_strdup(ctx->response_error), 256);
		}
		webpush_send_context_free(ctx);
	} else {
		success = TRUE;
	}
	return success;
}
