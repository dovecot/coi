/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "hmac.h"
#include "randgen.h"
#include "sha2.h"
#include "str.h"
#include "dcrypt.h"
#include "mail-storage-private.h"
#include "webpush-vapid.h"
#include "webpush-subscription.h"
#include "webpush-payload.h"
#include "webpush-payload-private.h"

#include "hex-binary.h"

/* Simplify code */
#define hkdf(m, salt, ikm, info, okm, okm_len) \
	hmac_hkdf((m), (salt)->data, (salt)->used, (ikm)->data, (ikm)->used, \
	(info)->data, (info)->used, (okm), (okm_len));
buffer_t *webpush_payload_pad_data(enum webpush_payload_encryption_type enc_type,
				   const buffer_t *plaintext, uint16_t pad_len)
{
	size_t buflen;
	uint16_t be;
	buffer_t *result;
	switch (enc_type) {
	case PAYLOAD_ENCRYPTION_TYPE_AESGCM:
		/* uint16 + padding */
		buflen = 2 + pad_len + plaintext->used;
		result = t_buffer_create(buflen);
		be = cpu16_to_be(pad_len);
		buffer_append(result, &be, sizeof(be));
		for (uint16_t i = 0; i < pad_len; i++) {
			unsigned char c = ((pad_len - i) % 256);
			buffer_append_c(result, c);
		}
		buffer_append(result, plaintext->data, plaintext->used);
		i_assert(result->used == buflen);
		break;
	case PAYLOAD_ENCRYPTION_TYPE_AES128GCM:
		/* 0x02 + padding */
		buflen = 1 + pad_len + plaintext->used;
		result = t_buffer_create(buflen);
		buffer_append(result, plaintext->data, plaintext->used);
		buffer_append_c(result, '\x02');
		/* add padding */
		for (uint16_t i = 0; i < pad_len; i++) {
			unsigned char c = ((pad_len - i) % 256);
			buffer_append_c(result, c);
		}
		i_assert(result->used == buflen);
		break;
	}
	return result;
}

void webpush_payload_calculate_key_nonce(enum webpush_payload_encryption_type enc_type,
					 const buffer_t *client_key,
					 const buffer_t *server_key,
					 const buffer_t *auth_data,
					 const buffer_t *S,
					 const buffer_t *salt,
					 buffer_t *key_r,
					 buffer_t *nonce_r)
{
	uint16_t be;
	buffer_t *prk = t_buffer_create(32);
	buffer_t *a_info;
	buffer_t *k_info = t_buffer_create(128);
	buffer_t *n_info = t_buffer_create(128);
	buffer_t *context = t_buffer_create(100);

	switch (enc_type) {
	/* RFC8291 draft 04 */
	case PAYLOAD_ENCRYPTION_TYPE_AESGCM:
		/* 3.4 Key Derivation Context */
		str_append(context, "P-256");
		buffer_append_c(context, '\0');
		be = cpu16_to_be(client_key->used);
		buffer_append(context, &be, sizeof(be));
		buffer_append(context, client_key->data, client_key->used);
		be = cpu16_to_be(server_key->used);
		buffer_append(context, &be, sizeof(be));
		buffer_append(context, server_key->data, server_key->used);
		/* 3.5 an Application server */
		a_info = t_buffer_create(24);
		str_append(a_info, "Content-Encoding: auth");
		buffer_append_c(a_info, '\0');
		/* cek info */
		str_append(k_info, "Content-Encoding: aesgcm");
		buffer_append_c(k_info, '\0');
		buffer_append(k_info, context->data, context->used);
		/* nonce info */
		str_append(n_info, "Content-Encoding: nonce");
		buffer_append_c(n_info, '\0');
		buffer_append(n_info, context->data, context->used);

		/* generate prk */
		hkdf(&hash_method_sha256, auth_data, S, a_info, prk, 32);
		/* generate key */
		hkdf(&hash_method_sha256, salt, prk, k_info, key_r, 16);
		/* generate nonce */
		hkdf(&hash_method_sha256, salt, prk, n_info, nonce_r, 12);
		break;
	/* RFC8291 */
	case PAYLOAD_ENCRYPTION_TYPE_AES128GCM:
		/* 3.3 Combining Shared and Authentication Secrets */
		str_append(context, "WebPush: info");
		buffer_append_c(context, '\0');
		buffer_append(context, client_key->data, client_key->used);
		buffer_append(context, server_key->data, server_key->used);

		/* 3.4 Encryption summary */
		str_append(k_info, "Content-Encoding: aes128gcm");
		buffer_append_c(k_info, '\0');
		str_append(n_info, "Content-Encoding: nonce");
		buffer_append_c(n_info, '\0');
		hkdf(&hash_method_sha256, auth_data, S, context, prk, 32);
		hkdf(&hash_method_sha256, salt, prk, k_info, key_r, 16);
		hkdf(&hash_method_sha256, salt, prk, n_info, nonce_r, 12);
		break;
	default:
		i_unreached();
	}
}

static int webpush_payload_aesgcm_encrypt(const buffer_t *plaintext,
					  const buffer_t *enc_key,
					  const buffer_t *enc_iv,
					  buffer_t *encrypted_r,
					  const char **error_r)
{
	struct dcrypt_context_symmetric *dctx;
	int ret;

	/* generate encryption context */
	if (!dcrypt_ctx_sym_create("id-aes128-GCM", DCRYPT_MODE_ENCRYPT, &dctx,
				   error_r))
		return -1;

	dcrypt_ctx_sym_set_key(dctx, enc_key->data, enc_key->used);
	dcrypt_ctx_sym_set_iv(dctx, enc_iv->data, enc_iv->used);
	dcrypt_ctx_sym_set_aad(dctx, &uchar_nul, 0);

	if (!dcrypt_ctx_sym_init(dctx, error_r) ||
	    !dcrypt_ctx_sym_update(dctx, plaintext->data, plaintext->used,
				   encrypted_r, error_r) ||
	    !dcrypt_ctx_sym_final(dctx, encrypted_r, error_r)) {
		ret = -1;
	} else {
		/* append tag */
		dcrypt_ctx_sym_get_tag(dctx, encrypted_r);
		ret = 0;
	}

	dcrypt_ctx_sym_destroy(&dctx);
	return ret;
}

int webpush_payload_encrypt(const struct webpush_subscription *subscription,
			    enum webpush_payload_encryption_type enc_type,
			    const buffer_t *plaintext, uint16_t padding,
			    buffer_t *ephemeral_key_r, buffer_t *salt_r,
			    buffer_t *encrypted_r, const char **error_r)
{
	struct dcrypt_public_key *client_pub_key;
	struct dcrypt_keypair as_keypair;
	enum dcrypt_key_type kt;
	const char *error;
	int ret;

	buffer_t *oid_buffer = t_buffer_create(8);
	buffer_t *dh256p_buffer = t_buffer_create(32);
	buffer_t *auth_buffer = t_buffer_create(32);

	buffer_t *shared_secret = t_buffer_create(100);
	buffer_t *sym_enc_key = t_buffer_create(16);
	buffer_t *sym_enc_nonce = t_buffer_create(12);

	if (webpush_subscription_extract_aesgcm_keys(subscription, auth_buffer,
						     dh256p_buffer, error_r) != 0)
		return -1;

	if (!dcrypt_initialize(NULL, NULL, &error)) {
		*error_r = t_strdup_printf("No crypto support available: %s",
					   error);
		return -1;
	}

	/* get prime256v1 oid */
	if (!dcrypt_name2oid(WEBPUSH_CURVE, oid_buffer, error_r))
		return -1;

	ARRAY_TYPE(dcrypt_raw_key) raw_key;
	t_array_init(&raw_key, 2);
	struct dcrypt_raw_key *param = array_append_space(&raw_key);
	param->parameter = oid_buffer->data;
	param->len = oid_buffer->used;
	param = array_append_space(&raw_key);
	param->parameter = dh256p_buffer->data;
	param->len = dh256p_buffer->used;

	/* load key */
	if (!dcrypt_key_load_public_raw(&client_pub_key, DCRYPT_KEY_EC, &raw_key,
					&error)) {
		*error_r = t_strdup_printf("Cannot load public key: %s", error);
		return -1;
	}

	/* generate keypair */
	if (!dcrypt_keypair_generate(&as_keypair, DCRYPT_KEY_EC, 0, WEBPUSH_CURVE,
				     error_r)) {
		dcrypt_key_unref_public(&client_pub_key);
		return -1;
	};

	/* derive a key */
	if (!dcrypt_ecdh_derive_secret(as_keypair.priv, client_pub_key,
				       shared_secret, error_r)) {
		dcrypt_keypair_unref(&as_keypair);
		dcrypt_key_unref_public(&client_pub_key);
		return -1;
	}
	dcrypt_key_unref_public(&client_pub_key);

	array_clear(&raw_key);
	if (!dcrypt_key_store_public_raw(as_keypair.pub, pool_datastack_create(),
					 &kt, &raw_key, error_r)) {
		dcrypt_keypair_unref(&as_keypair);
		return -1;
	}

	const struct dcrypt_raw_key *c_param = array_idx(&raw_key, 1);
	buffer_append(ephemeral_key_r, c_param->parameter, c_param->len);
	array_clear(&raw_key);
	dcrypt_keypair_unref(&as_keypair);

	/* fill in salt */
	random_fill(buffer_append_space_unsafe(salt_r, WEBPUSH_SALT_LEN),
		    WEBPUSH_SALT_LEN);

	buffer_t *to_crypt = webpush_payload_pad_data(enc_type, plaintext, padding);
	webpush_payload_calculate_key_nonce(enc_type, dh256p_buffer, ephemeral_key_r,
					    auth_buffer, shared_secret, salt_r,
					    sym_enc_key, sym_enc_nonce);
	ret = webpush_payload_aesgcm_encrypt(to_crypt, sym_enc_key, sym_enc_nonce,
					     encrypted_r, error_r);

	return ret;
}

int webpush_payload_sign(const buffer_t *payload, struct dcrypt_private_key *key,
			 string_t *b64_token_r, string_t *b64_key_r,
			 const char **error_r)
{
	buffer_t *sig = t_buffer_create(256);
	buffer_t *to_sign = t_buffer_create(256);
	buffer_t *jwk = t_buffer_create(256);
	string_t *hdr = t_str_new(64);

	struct dcrypt_public_key *pubkey = NULL;

	dcrypt_key_convert_private_to_public(key, &pubkey);
	if (!dcrypt_key_store_public(pubkey, DCRYPT_FORMAT_JWK, jwk, error_r)) {
		dcrypt_key_unref_public(&pubkey);
		return -1;
	}

	str_append(hdr, JWT_SIGN_HEADER);

	/* sign data */
	buffer_append(to_sign, hdr->data, hdr->used);
	buffer_append_c(to_sign, '.');
	buffer_append(to_sign, payload->data, payload->used);

	if (!dcrypt_sign(key, JWT_HASH, to_sign->data, to_sign->used,
			 sig, DCRYPT_PADDING_DEFAULT, error_r)) {
		dcrypt_key_unref_public(&pubkey);
		return -1;
	}
	dcrypt_key_unref_public(&pubkey);

	/* store everything */
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, 0,
			 hdr->data, hdr->used, b64_token_r);
	str_append_c(b64_token_r, '.');
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, 0,
			 payload->data, payload->used, b64_token_r);
	str_append_c(b64_token_r, '.');
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, 0,
			 sig->data, sig->used, b64_token_r);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, 0,
			 jwk->data, jwk->used, b64_key_r);
	return 0;
}
