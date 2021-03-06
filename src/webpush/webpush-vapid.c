/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "dcrypt.h"
#include "mail-storage-private.h"
#include "webpush-vapid.h"

#define WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PRIVATE_KEY \
	MAILBOX_ATTRIBUTE_WEBPUSH_PRIVATE_PREFIX"vapid_private_key"

static int
store_vapid_key(struct mailbox_transaction_context *t, struct dcrypt_keypair *pair,
		const char **error_r)
{
	struct mail_attribute_value value;
	buffer_t *buf_priv = t_buffer_create(256);
	i_zero(&value);
	/* export private key */
	if (!dcrypt_key_store_private(pair->priv, DCRYPT_FORMAT_DOVECOT, NULL,
				      buf_priv, NULL, NULL, error_r)) {
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

	return 0;
}

static int
generate_private_key(struct mailbox *box, struct dcrypt_private_key **priv_key_r)
{
	int ret;
	struct dcrypt_keypair pair;
	const char *curve, *error;

	/* try to open mailbox */
	if (mailbox_open(box) < 0)
		return -1;

	/* try to generate new key pair */
	curve = mail_user_plugin_getenv(box->storage->user,
					"webpush_vapid_curve");
	if (curve == NULL || *curve == '\0')
		curve = "prime256v1";
	if (!dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, curve, &error)) {
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
	} else if (mailbox_transaction_commit(&t) < 0) {
		i_error("Cannot commit VAPID keypair transaction: %s",
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		dcrypt_key_ref_private(pair.priv);
		*priv_key_r = pair.priv;
		ret = 0;
	}

	dcrypt_keypair_unref(&pair);
	return ret;
}

static int
get_vapid_private_dcrypt_key(struct mailbox *box,
			     struct dcrypt_private_key **priv_key_r)
{
	struct mail_attribute_value value;
	int ret;
	const char *error;

	/* try to load private key from attributes */
	ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				    WEBPUSH_INTERNAL_ATTRIBUTE_VAPID_PRIVATE_KEY,
				    &value);
	if (ret <= 0)
		return ret;

	/* load key */
	if (!dcrypt_key_load_private(priv_key_r, value.value, NULL, NULL,
				     &error)) {
		i_error("webpush: User has invalid VAPID key - regenerating: "
			"Can't load private key: %s", error);
		return 0;
	}
	return 1;
}

static bool
vapid_private_key_get_public_pem(struct dcrypt_private_key *priv_key,
				 string_t *key_str)
{
	struct dcrypt_public_key *pub_key;
	const char *error;
	bool ret = TRUE;

	dcrypt_key_convert_private_to_public(priv_key, &pub_key);
	if (!dcrypt_key_store_public(pub_key, DCRYPT_FORMAT_PEM,
				     key_str, &error)) {
		i_error("webpush: User has invalid VAPID key - regenerating: "
			"Can't store public key: %s", error);
		ret = FALSE;
	}
	dcrypt_key_unref_public(&pub_key);
	return ret;
}

int webpush_vapid_key_get(struct mailbox *box,
			  struct dcrypt_private_key **priv_key_r)
{
	const char *error;
	int ret;

	if (!dcrypt_initialize(NULL, NULL, &error)) {
		i_error("dcrypt_initialize() failed: %s", error);
		mail_storage_set_error(box->storage, MAIL_ERROR_UNAVAILABLE,
				       "No crypto support available");
		return -1;
	}

	/* try to use the existing key */
	if ((ret = get_vapid_private_dcrypt_key(box, priv_key_r)) < 0)
		return -1;
	if (ret == 0) {
		/* generate a missing key */
		if (generate_private_key(box, priv_key_r) < 0)
			return -1;
	}
	return 0;
}

static int
webpush_attribute_metadata_get_vapid_key(struct mailbox *box,
					 const char *key ATTR_UNUSED,
					 struct mail_attribute_value *value_r)
{
	struct dcrypt_private_key *priv_key;
	string_t *key_str = t_str_new(256);

	if (webpush_vapid_key_get(box, &priv_key) < 0)
		return -1;

	if (!vapid_private_key_get_public_pem(priv_key, key_str)) {
		if (generate_private_key(box, &priv_key) < 0)
			return -1;
		if (!vapid_private_key_get_public_pem(priv_key, key_str)) {
			mail_storage_set_critical(box->storage,
				"webpush: Failed to regenerate a usable vapid key");
			return -1;
		}
	}
	dcrypt_key_unref_private(&priv_key);

	/* we MUST have gotten something here */
	i_assert(str_len(key_str) > 0);

	value_r->value = str_c(key_str);

	return 1;
}

static const struct mailbox_attribute_internal
iattr_webpush_metadata_vapid_public_key = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_WEBPUSH_VAPID_PUBLIC_KEY,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.get = webpush_attribute_metadata_get_vapid_key,
};

void webpush_vapid_init(void)
{
	mailbox_attribute_register_internal(&iattr_webpush_metadata_vapid_public_key);
}
