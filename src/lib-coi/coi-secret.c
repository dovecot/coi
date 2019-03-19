/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "sha3.h"
#include "str.h"
#include "coi-contact.h"
#include "coi-secret.h"

static bool
coi_secret_verify_one(const char *secret_attempt, const struct sha3_ctx *sha3_ctx,
		      const unsigned char secret[STATIC_ARRAY SHA256_RESULTLEN])
{
	struct sha3_ctx sha3_ctx_dup = *sha3_ctx;
	unsigned char digest[SHA256_RESULTLEN];

	sha3_loop(&sha3_ctx_dup, secret_attempt, strlen(secret_attempt));
	sha3_256_result(&sha3_ctx_dup, digest);
	return memcmp(digest, secret, sizeof(digest)) == 0;
}

static bool
coi_secret_verify_array(const char *const *all_secrets, const struct sha3_ctx *sha3_ctx,
			const unsigned char secret[STATIC_ARRAY SHA256_RESULTLEN])
{
	for (unsigned int i = 0; all_secrets[i] != NULL; i++) {
		if (coi_secret_verify_one(all_secrets[i], sha3_ctx, secret))
			return TRUE;
	}
	return FALSE;
}

enum coi_secret_result
coi_secret_verify(const struct coi_secret_settings *set,
		  const struct coi_token *token)
{
	const char *prefix_end, *suffix, *secret_base64;

	i_assert(token->hash_algo == COI_HASH_ALGO_SHA3_256);

	/* secret is the encryption result. hash everything else. */
	prefix_end = strstr(token->token_string, "-secret:");
	i_assert(prefix_end != NULL);
	prefix_end += 8;
	suffix = strchr(prefix_end, '-');
	if (suffix == NULL) {
		suffix = "";
		secret_base64 = prefix_end;
	} else {
		secret_base64 = t_strdup_until(prefix_end, suffix);
	}

	/* add missing '=' so base64_decode() works */
	unsigned int len = strlen(secret_base64) % 4;
	if (len >= 2) {
		secret_base64 = t_strconcat(secret_base64,
					    len == 2 ? "==" : "=", NULL);
	}

	/* decode base64 secret */
	unsigned char secret[SHA256_RESULTLEN];
	buffer_t buf;
	buffer_create_from_data(&buf, secret, sizeof(secret));
	if (MAX_BASE64_ENCODED_SIZE(sizeof(secret)) != strlen(secret_base64) ||
	    base64_decode(secret_base64, strlen(secret_base64), NULL, &buf) < 0 ||
	    buf.used != sizeof(secret))
		return COI_SECRET_RESULT_NOTFOUND;

	/* initialize sha3 hash context with everything but the secret */
	struct sha3_ctx sha3_ctx;
	sha3_256_init(&sha3_ctx);
	sha3_loop(&sha3_ctx, token->token_string,
		  prefix_end - token->token_string);
	sha3_loop(&sha3_ctx, suffix, strlen(suffix));

	/* see if we can get a match for secret by using all of the
	   stored secrets */
	if (set->temp_secrets != NULL) {
		if (coi_secret_verify_array(set->temp_secrets, &sha3_ctx, secret))
			return COI_SECRET_RESULT_TEMP;
	}
	if (set->perm_secrets != NULL) {
		if (coi_secret_verify_array(set->perm_secrets, &sha3_ctx, secret))
			return COI_SECRET_RESULT_PERM;
	}
	return COI_SECRET_RESULT_NOTFOUND;
}

void coi_secret_append(string_t *dest, const char *token_prefix,
		       const char *secret)
{
	struct sha3_ctx sha3_ctx;
	unsigned char digest[SHA256_RESULTLEN];

	/* FIXME: using this for now, but most likely will need to change once
	   the spec is more finished. */
	sha3_256_init(&sha3_ctx);
	sha3_loop(&sha3_ctx, token_prefix, strlen(token_prefix));
	sha3_loop(&sha3_ctx, secret, strlen(secret));
	sha3_256_result(&sha3_ctx, digest);
	base64_encode(digest, sizeof(digest), dest);
	while (str_data(dest)[str_len(dest)-1] == '=')
		str_truncate(dest, str_len(dest)-1);
}

void coi_secret_settings_init(struct coi_secret_settings *set, pool_t pool,
			      const char *temp_secrets_str,
			      const char *perm_secrets_str)
{
	if (temp_secrets_str != NULL) {
		set->temp_secrets = (const char *const *)
			p_strsplit_spaces(pool, temp_secrets_str, " ");
	}
	if (perm_secrets_str != NULL) {
		set->perm_secrets = (const char *const *)
			p_strsplit_spaces(pool, perm_secrets_str, " ");
	}
}
