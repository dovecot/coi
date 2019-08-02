#ifndef WEBPUSH_PLUGIN_H
#define WEBPUSH_PLUGIN_H 1

/**
 This plugin is intended for generating vapid keys on-demand.
 The generated keys are stored in user attributes.

 Public key can be accessed using IMAP METADATA as

 /private/vendor/vendor.dovecot/webpush/vapid

 The private key is only accessible with mailbox_attribute_get
 with the MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PRIVATE_KEY
 constant.

 The actual keys are stored in internal locations.
**/

#define MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX "webpush/"

#define MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PUBLIC_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid"

#define MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PRIVATE_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid-private"

#endif