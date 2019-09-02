/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "array.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "randgen.h"
#include "str.h"
#include "dcrypt.h"
#include "webpush-subscription.h"
#include "webpush-payload.h"
#include "webpush-payload-private.h"

#define t_base64url_decode_str(x) t_base64url_decode_str(0, (x))
#define t_base64url_encode(d, l) \
	t_base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1, (d), (l))
static int
test_payload_encryption_encrypt(enum webpush_payload_encryption_type enc_type,
				const char *p256dh, const char *auth,
				buffer_t *peer_key, buffer_t *salt,
				buffer_t *encrypted)
{
	buffer_t payload;
	const char *error;

	buffer_create_from_const_data(&payload, "secret message", 14);

	/* make a subscription */
	struct webpush_subscription subs;
	t_array_init(&subs.resource_keys, 2);
	struct webpush_resource_key *key =
		array_append_space(&subs.resource_keys);
	key->key = "auth";
	key->value = auth;
	key = array_append_space(&subs.resource_keys);
	key->key = "p256dh";
	key->value = p256dh;
	error = NULL;

	uint16_t padding = nearest_power(payload.used);

	/* encrypt data */
	return webpush_payload_encrypt(&subs, enc_type,
				       &payload, padding, peer_key, salt,
				       encrypted, &error);
}

static int
test_payload_encryption_decrypt(enum webpush_payload_encryption_type enc_type,
				struct dcrypt_private_key *privkey,
				buffer_t *p256dh, buffer_t *R,
				buffer_t *auth_data, buffer_t *salt,
				buffer_t *encrypted, buffer_t *decrypted_r)
{
	struct dcrypt_context_symmetric *dctx;
	buffer_t *key = t_buffer_create(16);
	buffer_t *nonce = t_buffer_create(12);
	buffer_t *S = t_buffer_create(100);

	test_assert(dcrypt_ecdh_derive_secret_local(privkey, R, S, NULL));
	webpush_payload_calculate_key_nonce(enc_type, p256dh, R, auth_data, S,
					    salt, key, nonce);

	/* generate encryption context */
	if (!dcrypt_ctx_sym_create("id-aes128-GCM", DCRYPT_MODE_DECRYPT, &dctx,
				   NULL))
		return FALSE;

	int ret = 0;
	const char *error;

	/* remove tag at end */
	dcrypt_ctx_sym_set_key(dctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(dctx, nonce->data, nonce->used);
	dcrypt_ctx_sym_set_tag(dctx, CONST_PTR_OFFSET(encrypted->data, encrypted->used - 16), 16);
	if (!dcrypt_ctx_sym_init(dctx, &error) ||
	    !dcrypt_ctx_sym_update(dctx, encrypted->data, encrypted->used - 16,
				   decrypted_r, &error) ||
	    !dcrypt_ctx_sym_final(dctx, decrypted_r, &error)) {
		ret = -1;
	}

	if (ret == -1) {
		i_debug("error: %s", error);
		buffer_set_used_size(decrypted_r, 0);
		return -1;
	}

	const unsigned char *ptr = decrypted_r->data;
	uint16_t pad;

	switch (enc_type) {
	case PAYLOAD_ENCRYPTION_TYPE_AESGCM:
		/* remove padding */
		pad = be16_to_cpu_unaligned(ptr)+2;
		test_assert(pad < decrypted_r->used);
		if (pad < decrypted_r->used)
			buffer_delete(decrypted_r, 0, pad);
		else
			ret = -1;
		break;
	case PAYLOAD_ENCRYPTION_TYPE_AES128GCM:
		if ((ptr = memchr(ptr, '\x02', decrypted_r->used)) != NULL) {
			ptrdiff_t pad_pos = ptr - ((const unsigned char *)decrypted_r->data);
			if ((size_t)pad_pos < decrypted_r->used) {
				buffer_delete(decrypted_r, pad_pos, (size_t)-1);
			} else {
				ret = -1;
			}
		}
		break;
	default:
		i_unreached();
	}

	dcrypt_ctx_sym_destroy(&dctx);
	return ret;
}

static void test_key_nonce_aes128gcm(void)
{
	test_begin("key nonce generation (RFC 8291)");

	/* ephemeral key */
	buffer_t *as = t_base64url_decode_str("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy"
					      "27mlmlMoZIIgDll6e3vCYLocInmYWAmS"
					      "6TlzAC8wEqKK6PBru3jl7A8");
	/* client key */
	buffer_t *ua = t_base64url_decode_str("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-J"
					      "vLexhqUzORcx aOzi6-AYWXvTBHm4bjy"
					      "Pjs7Vd8pZGH6SRpkNtoIAiw4");
	/* salt */
	buffer_t *salt = t_base64url_decode_str("DGv6ra1nlYgDCS1FRnbzlw");
	/* auth */
	buffer_t *auth = t_base64url_decode_str("BTBZMqHH6r4Tts7J_aSIgg");
	/* S */
	buffer_t *S = t_base64url_decode_str("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhS"
					     "lknJ672kSs");

	buffer_t *ua_priv = t_base64url_decode_str("q1dXpw3UpT5VOmu_cf_v6ih07Ae"
						   "ms3njxI-JWgLcM94");

	buffer_t *exp_key = t_base64url_decode_str("oIhVW04MRdy2XN9CiKLxTg");
	buffer_t *exp_nonce = t_base64url_decode_str("4h_95klXJ5E_qnoN");

	buffer_t *key = t_buffer_create(16);
	buffer_t *nonce = t_buffer_create(12);

	webpush_payload_calculate_key_nonce(PAYLOAD_ENCRYPTION_TYPE_AES128GCM,
					    ua, as, auth, S, salt, key, nonce);

	test_assert(key->used == exp_key->used &&
		    memcmp(key->data, exp_key->data, key->used) == 0);
	test_assert(nonce->used == exp_nonce->used &&
		    memcmp(nonce->data, exp_nonce->data, nonce->used) == 0);

	buffer_t *oid_buffer = t_buffer_create(8);
	/* get prime256v1 oid */
	test_assert(dcrypt_name2oid(WEBPUSH_CURVE, oid_buffer, NULL));
	ARRAY_TYPE(dcrypt_raw_key) raw_key;
	t_array_init(&raw_key, 2);
	struct dcrypt_raw_key *param = array_append_space(&raw_key);
	param->parameter = oid_buffer->data;
	param->len = oid_buffer->used;
	param = array_append_space(&raw_key);
	param->parameter = ua_priv->data;
	param->len = ua_priv->used;
	struct dcrypt_private_key *privkey;
	dcrypt_key_load_private_raw(&privkey, DCRYPT_KEY_EC, &raw_key, NULL);

	buffer_t *encrypted = t_base64url_decode_str(
		"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27"
		"mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6"
		"cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulc"
		"y4a-fN");

	buffer_delete(encrypted, 0, 86);
	buffer_t *decrypted = t_buffer_create(256);

	test_assert(test_payload_encryption_decrypt(PAYLOAD_ENCRYPTION_TYPE_AES128GCM,
						    privkey, ua, as, auth, salt,
						    encrypted, decrypted) == 0);

	test_assert_strcmp(str_c(decrypted), "When I grow up, I want to be a "
					     "watermelon");

	dcrypt_key_unref_private(&privkey);

	test_end();
}

static void test_payload_encryption(void)
{
	struct dcrypt_keypair pair;
	const struct dcrypt_raw_key *raw_key;
	const char *p256dh;
	const char *authstr;
	enum dcrypt_key_type kt;
	unsigned char auth[16];
	buffer_t p256dh_b, auth_b;

	ARRAY_TYPE(dcrypt_raw_key) pub_raw;
	buffer_t *peer_key_buf, *salt, *encrypted, *decrypted;
	test_begin("payload encryption");

	random_fill(auth, sizeof(auth));

	peer_key_buf = t_buffer_create(32);
	salt = t_buffer_create(16);
	encrypted = t_buffer_create(64);
	decrypted = t_buffer_create(64);

	/* generate keypair */
	test_assert(dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0,
					    "prime256v1", NULL));
	t_array_init(&pub_raw, 2);
	test_assert(dcrypt_key_store_public_raw(pair.pub, pool_datastack_create(),
						&kt, &pub_raw, NULL));
	test_assert(kt == DCRYPT_KEY_EC);
	raw_key = array_idx(&pub_raw, 1);
	p256dh = str_c(t_base64url_encode(raw_key->parameter, raw_key->len));
	buffer_create_from_const_data(&p256dh_b, raw_key->parameter, raw_key->len);
	authstr = str_c(t_base64url_encode(auth, sizeof(auth)));
	buffer_create_from_const_data(&auth_b, auth, sizeof(auth));

	test_assert(test_payload_encryption_encrypt(PAYLOAD_ENCRYPTION_TYPE_AESGCM,
						    p256dh, authstr, peer_key_buf,
						    salt, encrypted) == 0);

	test_assert(peer_key_buf->used > 0);
	test_assert(salt->used > 0);
	test_assert(encrypted->used > 0);

	test_assert(test_payload_encryption_decrypt(PAYLOAD_ENCRYPTION_TYPE_AESGCM,
						    pair.priv, &p256dh_b,
						    peer_key_buf, &auth_b,
						    salt, encrypted, decrypted) == 0);

	test_assert_strcmp(str_c(decrypted), "secret message");

	buffer_set_used_size(peer_key_buf, 0);
	buffer_set_used_size(salt, 0);
	buffer_set_used_size(encrypted, 0);
	buffer_set_used_size(decrypted, 0);

	test_assert(test_payload_encryption_encrypt(PAYLOAD_ENCRYPTION_TYPE_AES128GCM,
						    p256dh, authstr, peer_key_buf,
						    salt, encrypted) == 0);

	test_assert(peer_key_buf->used > 0);
	test_assert(salt->used > 0);
	test_assert(encrypted->used > 0);

	test_assert(test_payload_encryption_decrypt(PAYLOAD_ENCRYPTION_TYPE_AES128GCM,
						    pair.priv, &p256dh_b,
						    peer_key_buf, &auth_b,
						    salt, encrypted, decrypted) == 0);

	test_assert_strcmp(str_c(decrypted), "secret message");

	dcrypt_keypair_unref(&pair);

	test_end();
}

static const char *jwt_header = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
static const char *jwt_body = "{\"aud\":\"https://push.example.net\","
			      "\"exp\":1453523768,\"sub\":"
			      "\"mailto:push@example.com\"}";

static void test_payload_signing_verify(struct dcrypt_public_key *pubkey2,
					string_t *token, string_t *k)
{
	const char *const *parts = t_strsplit(str_c(token), ".");
	buffer_t *hdr = t_base64url_decode_str(parts[0]);
	buffer_t *body = t_base64url_decode_str(parts[1]);
	buffer_t *to_verify = t_buffer_create(hdr->used + body->used);
	buffer_t *sig = t_base64url_decode_str(parts[2]);
	buffer_t *raw_dec = t_base64url_decode_str(str_c(k));
	buffer_t *oid_buffer = t_buffer_create(80);
	bool valid = FALSE;
	struct dcrypt_public_key *pubkey;
	test_assert(dcrypt_name2oid(WEBPUSH_CURVE, oid_buffer, NULL));
	ARRAY_TYPE(dcrypt_raw_key) raw_key;
	t_array_init(&raw_key, 2);
	struct dcrypt_raw_key *param = array_append_space(&raw_key);
	param->parameter = oid_buffer->data;
	param->len = oid_buffer->used;
	param = array_append_space(&raw_key);
	param->parameter = raw_dec->data;
	param->len = raw_dec->used;
	test_assert(dcrypt_key_load_public_raw(&pubkey, DCRYPT_KEY_EC, &raw_key, NULL));
	test_assert_strcmp(str_c(hdr), jwt_header);
	test_assert_strcmp(str_c(body), jwt_body);
	buffer_append(to_verify, parts[0], strlen(parts[0]));
	buffer_append_c(to_verify, '.');
	buffer_append(to_verify, parts[1], strlen(parts[1]));

	test_assert(dcrypt_verify(pubkey, "sha256", DCRYPT_SIGNATURE_FORMAT_X962,
				  to_verify->data, to_verify->used,
				  sig->data, sig->used, &valid, DCRYPT_PADDING_DEFAULT,
				  NULL) && valid);
	buffer_t *key_id_1 = t_buffer_create(32);
	buffer_t *key_id_2 = t_buffer_create(32);
	test_assert(dcrypt_key_id_public(pubkey, "sha256", key_id_1, NULL));
	test_assert(dcrypt_key_id_public(pubkey2, "sha256", key_id_2, NULL));
	test_assert(key_id_1->used == key_id_2->used && key_id_1->used > 0 &&
		    memcmp(key_id_1->data, key_id_2->data, key_id_1->used) == 0);
	dcrypt_key_unref_public(&pubkey);
}

static void test_payload_signing(void)
{
	struct dcrypt_keypair pair;
	const char *error ATTR_UNUSED;
	string_t *token = t_str_new(256);
	string_t *key = t_str_new(256);
	buffer_t body;
	buffer_create_from_const_data(&body, jwt_body, strlen(jwt_body));

	test_begin("sign payload");
	test_assert(dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0,
					    "prime256v1", NULL));

	test_assert(webpush_payload_sign(&body, pair.priv, token, key,
		    &error) == 0);
	test_payload_signing_verify(pair.pub, token, key);

	dcrypt_keypair_unref(&pair);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_key_nonce_aes128gcm,
		test_payload_encryption,
		test_payload_signing,
		NULL
	};

	i_assert(dcrypt_initialize(NULL, NULL, NULL));

	return test_run(test_functions);
}
