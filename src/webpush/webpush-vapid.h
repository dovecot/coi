#ifndef WEBPUSH_VAPID_H
#define WEBPUSH_VAPID_H

#include "webpush-plugin.h"

/**
 The VAPID keys are generated on-demand. The private key is stored in an
 internal attribute. The public key is generated from the stored private key.

 Public key can be accessed using IMAP METADATA as

 /private/vendor/vendor.dovecot/webpush/vapid

 The private key is only accessible with mailbox_attribute_get
 with the MAILBOX_ATTRIBUTE_WEBPUSH_VAPID_PRIVATE_KEY
 constant.
**/

#define MAILBOX_ATTRIBUTE_WEBPUSH_VAPID_PUBLIC_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid"

#define MAILBOX_ATTRIBUTE_WEBPUSH_VAPID_PRIVATE_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid-private"

void webpush_vapid_init(void);

#endif
