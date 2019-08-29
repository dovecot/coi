#ifndef WEBPUSH_VAPID_H
#define WEBPUSH_VAPID_H

#include "webpush-plugin.h"

/**
 The VAPID keys are generated on-demand. The private key is stored in an
 internal attribute. The public key is generated from the stored private key.

 Public key can be accessed using IMAP METADATA as

 /private/vendor/vendor.dovecot/webpush/vapid
**/

#define MAILBOX_ATTRIBUTE_WEBPUSH_VAPID_PUBLIC_KEY \
	MAILBOX_ATTRIBUTE_WEBPUSH_PUBLIC_PREFIX"vapid"

void webpush_vapid_init(void);

#endif
