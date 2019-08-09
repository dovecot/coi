#ifndef WEBPUSH_PLUGIN_H
#define WEBPUSH_PLUGIN_H 1

struct module;

/* Prefix for all publicly accessible webpush attributes.
   Note that this may change at some point after becoming a standard, so
   it shouldn't be used in permanent attribute storage paths. */
#define MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_PREFIX \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	"vendor/vendor.dovecot/webpush/"

/* Prefix for webpush attributes that shouldn't be accessible to regular
   users/clients. */
#define MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_PREFIX \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"webpush/"

void webpush_plugin_init(struct module *module);
void webpush_plugin_deinit(void);

#endif
