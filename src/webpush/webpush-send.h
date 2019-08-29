#ifndef WEBPUSH_SEND_H
#define WEBPUSH_SEND_H

struct dcrypt_private_key;
struct webpush_subscription;

struct webpush_notify_global {
	int refcount;
	struct http_client *http_client;
};

extern struct webpush_notify_global *webpush_global;

/* Try to send push-notification. Returns TRUE if sending was attempted,
   FALSE if webpush hasn't been configured properly. */
bool webpush_send(struct mail_user *user,
		  const struct webpush_subscription *subscription,
		  struct dcrypt_private_key *vapid_key,
		  string_t *msg, const char **error_r);

#endif
