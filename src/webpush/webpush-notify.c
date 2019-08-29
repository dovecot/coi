/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "ioloop.h"
#include "istream.h"
#include "settings-parser.h"
#include "str.h"
#include "module-context.h"
#include "message-size.h"
#include "http-client.h"
#include "dcrypt.h"

#include "push-notification-plugin.h"
#include "push-notification-drivers.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-events.h"
#include "push-notification-txn-msg.h"

#include "coi-common.h"
#include "webpush-subscription.h"
#include "webpush-message.h"
#include "webpush-send.h"
#include "webpush-vapid.h"
#include "webpush-notify.h"

#define DEFAULT_CACHE_LIFETIME_SECS 60
#define DEFAULT_TIMEOUT_MSECS 2000
#define DEFAULT_RETRY_COUNT 1

#define WEBPUSH_BODY_STRDUP_MAX_LEN 4096
#define WEBPUSH_FOLDER_MAX_LEN 1000

struct webpush_event_messagenew_save_data {
	const char *group_id;
	const char *hdr_content_type;
	const char *hdr_content_transfer_encoding;
	const char *body;
};

extern struct push_notification_event push_notification_event_messagenew;

static struct push_notification_event webpush_event_messagenew;
static void (*webpush_event_messagenew_save_prev)
	(struct push_notification_txn *ptxn,
	 struct push_notification_event_config *ec,
	 struct push_notification_txn_msg *msg,
	 struct mail *mail);

static struct push_notification_event event_webpush = {
	.name = "webpush",
};
static struct push_notification_event_config ec_webpush = {
	.event = &event_webpush,
};

struct webpush_mail_user_module webpush_mail_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static int
webpush_notify_init(struct push_notification_driver_config *config,
		    struct mail_user *user, pool_t pool,
		    void **context, const char **error_r)
{
	struct webpush_notify_config *dconfig;
	const char *error, *tmp;

	dconfig = p_new(pool, struct webpush_notify_config, 1);
	dconfig->event = event_create(user->event);
	event_add_category(dconfig->event, &event_category_push_notification);
	event_set_append_log_prefix(dconfig->event, "webpush: ");

	tmp = hash_table_lookup(config->config, (const char *)"cache_lifetime");
	if (tmp == NULL)
		dconfig->cache_lifetime_secs = DEFAULT_CACHE_LIFETIME_SECS;
	else if (settings_get_time(tmp, &dconfig->cache_lifetime_secs, &error) < 0) {
		event_unref(&dconfig->event);
		*error_r = t_strdup_printf("Failed to parse cache_lifetime %s: %s",
					   tmp, error);
		return -1;
	}

	tmp = hash_table_lookup(config->config, (const char *)"max_retries");
	if (tmp == NULL ||
	    str_to_uint(tmp, &dconfig->http_max_retries) < 0) {
		dconfig->http_max_retries = DEFAULT_RETRY_COUNT;
	}
	tmp = hash_table_lookup(config->config, (const char *)"timeout_msecs");
	if (tmp == NULL ||
	    str_to_uint(tmp, &dconfig->http_timeout_msecs) < 0) {
		dconfig->http_timeout_msecs = DEFAULT_TIMEOUT_MSECS;
	}
	tmp = hash_table_lookup(config->config, (const char *)"rawlog_dir");
	dconfig->http_rawlog_dir = i_strdup(tmp);

	if (webpush_global == NULL) {
		webpush_global = i_new(struct webpush_notify_global, 1);
		webpush_global->refcount = 0;
	}

	struct webpush_mail_user *wuser =
		p_new(user->pool, struct webpush_mail_user, 1);
	wuser->dconfig = dconfig;
	MODULE_CONTEXT_SET(user, webpush_mail_user_module, wuser);

	webpush_global->refcount++;
	*context = dconfig;
	return 0;
}

static int
webpush_notify_read_config(struct mail_user *user, pool_t pool,
			   ARRAY_TYPE(webpush_subscription) *subscriptions,
			   struct dcrypt_private_key **vapid_key_r)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box;
	int ret;

	box = mailbox_alloc(ns->list, "INBOX", 0);
	ret = webpush_subscriptions_read(box, pool, TRUE, subscriptions);
	if (ret == 0)
		ret = webpush_vapid_key_get(box, vapid_key_r);
	mailbox_free(&box);
	return ret;
}

static bool
webpush_notify_cache_get(struct push_notification_driver_txn *dtxn,
			 bool force_cache,
			 struct webpush_notify_cache **cache_r)
{
	struct webpush_notify_config *dconfig = dtxn->duser->context;
	struct webpush_notify_cache *cache = &dconfig->cache;

	if (ioloop_time < cache->expire_time || force_cache) {
		/* use the existing cache */
		if (cache->expire_time == 0)
			return FALSE; /* previous lookup failed */
		*cache_r = cache;
		return TRUE;
	}

	if (cache->pool == NULL) {
		cache->pool = pool_alloconly_create(
			MEMPOOL_GROWING"webpush notify cache", 1024);
	} else {
		if (cache->vapid_key != NULL)
			dcrypt_key_unref_private(&cache->vapid_key);
		p_clear(cache->pool);
	}

	/* read existing subscriptions and vapid key */
	p_array_init(&cache->subscriptions, cache->pool,
		     WEBPUSH_DEFAULT_SUBSCRIPTION_LIMIT);
	if (webpush_notify_read_config(dtxn->ptxn->muser, cache->pool,
				       &cache->subscriptions,
				       &cache->vapid_key) < 0)
		return FALSE;

	cache->expire_time = ioloop_time + dconfig->cache_lifetime_secs;
	*cache_r = cache;
	return TRUE;
}

static bool
webpush_notify_begin_txn(struct push_notification_driver_txn *dtxn)
{
	struct push_notification_event_messagenew_config *config;
	struct webpush_notify_cache *cache;

	if (!webpush_notify_cache_get(dtxn, FALSE, &cache) ||
	    array_count(&cache->subscriptions) == 0) {
		/* no configured push notifications */
		return FALSE;
	}

	config = p_new(dtxn->ptxn->pool,
		       struct push_notification_event_messagenew_config, 1);
	config->flags = PUSH_NOTIFICATION_MESSAGE_HDR_FROM |
		PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT |
		PUSH_NOTIFICATION_MESSAGE_HDR_MESSAGE_ID |
		PUSH_NOTIFICATION_MESSAGE_HDR_DATE |
		PUSH_NOTIFICATION_MESSAGE_KEYWORDS;
	push_notification_event_init(dtxn, "MessageNew", config);
	return TRUE;
}

static bool
webpush_notify_subscription_want(const struct webpush_subscription *subscription,
				 const struct push_notification_event_messagenew_data *messagenew)
{
	bool is_chat, want_chat;

	switch (subscription->msgtype) {
	case WEBPUSH_SUBSCRIPTION_MSGTYPE_UNKNOWN:
		i_unreached();
	case WEBPUSH_SUBSCRIPTION_MSGTYPE_ANY:
		return TRUE;
	case WEBPUSH_SUBSCRIPTION_MSGTYPE_CHAT:
		want_chat = TRUE;
		break;
	case WEBPUSH_SUBSCRIPTION_MSGTYPE_EMAIL:
		want_chat = FALSE;
		break;
	}
	is_chat = messagenew->keywords != NULL &&
		str_array_icase_find(messagenew->keywords, COI_KEYWORD_CHAT);
	return want_chat == is_chat;
}

static int
webpush_notify_enforce_subscription_limit(struct mail_user *user,
					  struct push_notification_driver_txn *dtxn,
					  struct webpush_notify_cache *cache)
{
	unsigned int limit = webpush_subscription_get_limit(user);
	if (array_count(&cache->subscriptions) <= limit)
		return 0;

	/* too many subscriptions. remove the oldest ones. */
	struct mail_namespace *ns =
		mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX", 0);
	int ret = webpush_subscription_delete_oldest(box, limit);
	mailbox_free(&box);

	if (ret < 0)
		return -1;

	/* refresh cache */
	cache->expire_time = 0;
	if (!webpush_notify_cache_get(dtxn, FALSE, &cache))
		return -1; /* metadata lookups failed */
	return 0;
}

static void
webpush_notify_process_msg(struct push_notification_driver_txn *dtxn,
			   struct push_notification_txn_msg *msg)
{
	struct mail_user *user = dtxn->ptxn->muser;
	const struct push_notification_event_messagenew_data *messagenew;
	const struct webpush_event_messagenew_save_data *webpush_data;
	struct webpush_notify_cache *cache;
	const struct webpush_subscription *subscription;
	const char *error;

	messagenew = push_notification_txn_msg_get_eventdata(msg, "MessageNew");
	if (messagenew == NULL)
		return; /* not a MessageNew event */
	webpush_data = push_notification_txn_msg_get_eventdata(msg, event_webpush.name);
	i_assert(webpush_data != NULL);

	if (strlen(msg->mailbox) > WEBPUSH_FOLDER_MAX_LEN) {
		/* Don't send the push-notification at all if the folder name
		   takes up too much space. There's no point in truncating the
		   name or sending a notification without the folder. */
		return;
	}

	if (!webpush_notify_cache_get(dtxn, TRUE, &cache))
		return; /* metadata lookups failed */

	if (webpush_notify_enforce_subscription_limit(user, dtxn, cache) < 0)
		return;

	struct webpush_message_input input = {
		.mailbox_vname = msg->mailbox,
		.uid_validity = msg->uid_validity,
		.uid = msg->uid,
		.date = messagenew->date,
		.hdr_from = messagenew->from,
		.hdr_subject = messagenew->subject,
		.hdr_message_id = messagenew->message_id,
		.chat_group_id = webpush_data->group_id,
		.hdr_content_type = webpush_data->hdr_content_type,
		.hdr_content_transfer_encoding = webpush_data->hdr_content_transfer_encoding,
		.body = webpush_data->body,
	};
	string_t *msg_text = str_new(default_pool, 256);
	webpush_message_write(msg_text, &input);

	/* check if msgtype matches wanted subscriptions */
	array_foreach(&cache->subscriptions, subscription) {
		if (!webpush_notify_subscription_want(subscription, messagenew))
			continue;
		(void)webpush_send(user, subscription, cache->vapid_key,
				   msg_text, &error);
	}
}

static void
webpush_notify_deinit(struct push_notification_driver_user *duser)
{
	struct webpush_notify_config *dconfig = duser->context;

	if (webpush_global != NULL) {
		if (webpush_global->http_client != NULL)
			http_client_wait(webpush_global->http_client);
		i_assert(webpush_global->refcount > 0);
		webpush_global->refcount--;
	}
	i_free(dconfig->http_rawlog_dir);
	if (dconfig->cache.vapid_key != NULL)
		dcrypt_key_unref_private(&dconfig->cache.vapid_key);
	pool_unref(&dconfig->cache.pool);
	event_unref(&dconfig->event);
}

static void webpush_notify_cleanup(void)
{
	if (webpush_global == NULL || webpush_global->refcount > 0)
		return;
	i_assert(webpush_global->refcount == 0);

	if (webpush_global->http_client != NULL)
		http_client_deinit(&webpush_global->http_client);
	i_free_and_null(webpush_global);
}

static int
webpush_messagenew_save_body(struct push_notification_txn *ptxn,
			     struct mail *mail,
			     struct webpush_event_messagenew_save_data *webpush_data)
{
	struct message_size body_size;
	struct istream *input;
	const unsigned char *data;
	size_t size;

	if (mail_get_stream_because(mail, NULL, &body_size,
				    "webpush notification", &input) < 0)
		return -1;
	if (body_size.physical_size > WEBPUSH_BODY_STRDUP_MAX_LEN)
		return 0;

	string_t *str = t_str_new(body_size.physical_size);
	while (i_stream_read_more(input, &data, &size) > 0) {
		if (memchr(data, 0, size) != NULL)
			return 0;
		str_append_data(str, data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0)
		return 0;

	/* The body seems to be usable. Get also Content-Type and
	   Content-Transfer-Encoding headers. */
	const char *content_type, *content_transfer_encoding;
	if (mail_get_first_header(mail, "Content-Type", &content_type) < 0 ||
	    mail_get_first_header(mail, "Content-Transfer-Encoding",
				  &content_transfer_encoding) < 0) {
		/* body isn't usable if these aren't known */
		return -1;
	}

	webpush_data->body = p_strdup(ptxn->pool, str_c(str));
	webpush_data->hdr_content_type = p_strdup(ptxn->pool, content_type);
	webpush_data->hdr_content_transfer_encoding =
		p_strdup(ptxn->pool, content_transfer_encoding);
	return 0;
}

static void
webpush_event_messagenew_save(struct push_notification_txn *ptxn,
			      struct push_notification_event_config *ec,
			      struct push_notification_txn_msg *msg,
			      struct mail *mail)
{
	struct webpush_event_messagenew_save_data *webpush_data;
	const char *group_id;

	webpush_data = push_notification_txn_msg_get_eventdata(msg, event_webpush.name);
	if (webpush_data == NULL) {
		webpush_data = p_new(ptxn->pool,
				     struct webpush_event_messagenew_save_data, 1);
		push_notification_txn_msg_set_eventdata(ptxn, msg, &ec_webpush, webpush_data);
	}

	/* save the body if it looks like it might be small enough to fit to
	   the push-notification */
	T_BEGIN {
		(void)webpush_messagenew_save_body(ptxn, mail, webpush_data);
	} T_END;

	if (coi_mail_parse_group(mail, &group_id) > 0)
		webpush_data->group_id = p_strdup(ptxn->pool, group_id);

	webpush_event_messagenew_save_prev(ptxn, ec, msg, mail);
}

static const struct push_notification_driver push_notification_driver_webpush = {
	.name = "webpush",
	.v = {
		.init = webpush_notify_init,
		.begin_txn = webpush_notify_begin_txn,
		.process_msg = webpush_notify_process_msg,
		.deinit = webpush_notify_deinit,
		.cleanup = webpush_notify_cleanup
	}
};

void webpush_notify_register(void)
{
	webpush_event_messagenew = push_notification_event_messagenew;
	webpush_event_messagenew_save_prev =
		webpush_event_messagenew.msg_triggers.save;
	webpush_event_messagenew.msg_triggers.save =
		webpush_event_messagenew_save;
	push_notification_event_unregister(&push_notification_event_messagenew);
	push_notification_event_register(&webpush_event_messagenew);

	push_notification_driver_register(&push_notification_driver_webpush);
}

void webpush_notify_unregister(void)
{
	push_notification_driver_unregister(&push_notification_driver_webpush);

	push_notification_event_unregister(&webpush_event_messagenew);
	push_notification_event_register(&push_notification_event_messagenew);
}
