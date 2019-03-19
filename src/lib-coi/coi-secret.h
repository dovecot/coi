#ifndef COI_SECRET_H
#define COI_SECRET_H

struct coi_token;

enum coi_secret_result {
	COI_SECRET_RESULT_NOTFOUND,
	COI_SECRET_RESULT_TEMP,
	COI_SECRET_RESULT_PERM,
};

struct coi_secret_settings {
	const char *const *temp_secrets;
	const char *const *perm_secrets;
};

enum coi_secret_result
coi_secret_verify(const struct coi_secret_settings *set,
		  const struct coi_token *token);

void coi_secret_append(string_t *dest, const char *token_prefix,
		       const char *secret);

void coi_secret_settings_init(struct coi_secret_settings *set, pool_t pool,
			      const char *temp_secrets_str,
			      const char *perm_secrets_str);

#endif
