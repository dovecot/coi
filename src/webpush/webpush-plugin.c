/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "dcrypt.h"
#include "mail-storage-private.h"
#include "webpush-plugin.h"

#define WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PRIVATE_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid_private_key"

#define WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PUBLIC_KEY \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX"vapid_public_key"

const char *webpush_plugin_version = DOVECOT_ABI_VERSION;

static int
store_vapid_key(struct mailbox_transaction_context *t, struct dcrypt_keypair *pair,
		const char **error_r)
{
	struct mail_attribute_value value;
	buffer_t *buf_priv = t_buffer_create(256);
	buffer_t *buf_pub = t_buffer_create(256);
	i_zero(&value);
	value.last_change = ioloop_time;
	/* export private key */
	if (!dcrypt_key_store_private(pair->priv, DCRYPT_FORMAT_DOVECOT, NULL,
				      buf_priv, NULL, NULL, error_r)) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_TEMP,
				       "Cannot generate crypto key");
		return -1;
	}

	if (!dcrypt_key_store_public(pair->pub, DCRYPT_FORMAT_DOVECOT,
				     buf_pub, error_r)) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_TEMP,
				       "Cannot generate crypto key");
		return -1;
	}

	value.value = str_c(buf_priv);
	if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				  WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PRIVATE_KEY,
				  &value) < 0) {
		*error_r = mail_storage_get_last_internal_error(t->box->storage, NULL);
		return -1;
	}

	value.value = str_c(buf_pub);
	if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				  WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PUBLIC_KEY,
				  &value) < 0) {
		*error_r = mail_storage_get_last_internal_error(t->box->storage, NULL);
		return -1;
	}

	return 0;
}

static int
generate_private_key(struct mailbox *box, const char *curve)
{
	int ret;
	struct dcrypt_keypair pair;
	const char *error;

	/* try to open mailbox */
	if (mailbox_open(box) < 0)
		return -1;

	/* try to generate new key pair */
	/* FIXME: Move curve selection to configuration */
	if (!dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, curve,
				     &error)) {
		i_error("dcrypt_keypair_generate(%s): %s", curve, error);
		mail_storage_set_error(box->storage, MAIL_ERROR_TEMP,
				      "Cannot generate crypto key");
		return -1;
	}

	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box, 0, "VAPID key storage");

	if (store_vapid_key(t, &pair, &error) < 0) {
		i_error("Cannot save VAPID keypair: %s", error);
		mailbox_transaction_rollback(&t);
		ret = -1;
	} else {
		mailbox_transaction_commit(&t);
		ret = 0;
	}

	dcrypt_keypair_unref(&pair);
	mailbox_close(box);

	return ret;
}

static int
get_vapid_public_key(struct mailbox *box, buffer_t *tmp_buffer)
{
	struct mail_attribute_value value;
	int ret;
	const char *error;
	i_zero(&value);

	/* try to load public key from attributes */
	if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
					WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PUBLIC_KEY,
					&value)) > 0) {
		/* load key */
		struct dcrypt_public_key *tmp_key = NULL;
		if (dcrypt_key_load_public(&tmp_key, value.value, &error) &&
		    dcrypt_key_store_public(tmp_key, DCRYPT_FORMAT_PEM, tmp_buffer,
					    &error)) {
			dcrypt_key_unref_public(&tmp_key);
			return 1;
		} else {
			i_warning("Generating new VAPID key, cannot load user's"
				  " current VAPID key: %s", error);
		}
		dcrypt_key_unref_public(&tmp_key);
	} else if (ret == -1)
		return -1;
	return 0;
}

static int
get_vapid_private_key(struct mailbox *box, buffer_t *tmp_buffer)
{
	struct mail_attribute_value value;
	int ret;
	const char *error;
	i_zero(&value);

	/* try to load private key from attributes */
	if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
					WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PRIVATE_KEY,
					&value)) > 0) {
		/* load key */
		struct dcrypt_private_key *tmp_key = NULL;
		if (dcrypt_key_load_private(&tmp_key, value.value, NULL, NULL,
					    &error) &&
		    dcrypt_key_store_private(tmp_key, DCRYPT_FORMAT_PEM, NULL,
					     tmp_buffer, NULL, NULL, &error)) {
			dcrypt_key_unref_private(&tmp_key);
			return 1;
		} else {
			i_warning("Generating new VAPID key, cannot load user's"
				  " current VAPID key: %s", error);
		}
		dcrypt_key_unref_private(&tmp_key);
	} else if (ret == -1)
		return -1;
	return 0;
}

static int
webpush_attribute_metadata_get_vapid_key(struct mailbox *box, const char *key,
					 struct mail_attribute_value *value_r)
{
	const char *error;

	buffer_t *key_buffer = t_buffer_create(256);
	int ret;

	if (!box->inbox_user) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				       "WebPush VAPID key is only available via"
				       " INBOX");
		return -1;
	}

	if (!dcrypt_initialize(NULL, NULL, &error)) {
		i_error("dcrypt_initialize() failed: %s", error);
		mail_storage_set_error(box->storage, MAIL_ERROR_UNAVAILABLE,
				       "No crypto support available");
		return -1;
	}

	const char *curve = mail_user_plugin_getenv(box->storage->user, "vapid_curve");
	if (curve == NULL || *curve == '\0')
		curve = "prime256v1";

	for(int i = 0; i < 1; i++) {
		if (strcmp(key, MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PUBLIC_KEY) == 0) {
			if ((ret = get_vapid_public_key(box, key_buffer)) == 1) {
				break;
			} else if (ret == 0) {
				if (generate_private_key(box, curve) < 0)
					return -1;
			} else {
				return -1;
			}
		} else if (strcmp(key, MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PRIVATE_KEY) == 0) {
			if ((ret = get_vapid_private_key(box, key_buffer)) == 1) {
				break;
			} else if (ret == 0) {
				if (generate_private_key(box, curve) < 0)
					return -1;
			} else {
				return -1;
			}
		} else {
			i_unreached();
		}
	}

	value_r->value = str_c(key_buffer);

	return 1;
}

static const struct mailbox_attribute_internal
iattr_webpush_metadata_vapid_private_key = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PUBLIC_KEY,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.get = webpush_attribute_metadata_get_vapid_key,
};

static const struct mailbox_attribute_internal
iattr_webpush_metadata_vapid_public_key = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_WEBPUSH_METADATA_VAPID_PRIVATE_KEY,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.get = webpush_attribute_metadata_get_vapid_key,
};

void webpush_plugin_init(struct module *module);
void webpush_plugin_deinit(void);

void webpush_plugin_init(struct module *module ATTR_UNUSED)
{
	mailbox_attribute_register_internal(&iattr_webpush_metadata_vapid_public_key);
	mailbox_attribute_register_internal(&iattr_webpush_metadata_vapid_private_key);
}

void webpush_plugin_deinit(void)
{
}

const char *webpush_plugin_dependencies[] = { NULL };