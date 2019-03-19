#ifndef COI_CONTACT_H
#define COI_CONTACT_H

struct coi_secret_settings;

#define COI_HDR_TOKEN_IN "COI-TokenIn"
#define COI_HDR_TOKEN_OUT "COI-TokenOut"
#define COI_HDR_FROM_HASH "COI-From-Hash"

enum coi_hash_algo {
	COI_HASH_ALGO_SHA3_256 = 0,
};
#define COI_HASH_ALGO_DEFAULT COI_HASH_ALGO_SHA3_256

struct coi_token_option {
	const char *key, *value;
};

struct coi_token {
	/* The original unparsed token string. */
	const char *token_string;

	/* Secret token part */
	const char *secret;

	/* Timestamp when token was created */
	time_t create_time;
	/* How many seconds the token is valid */
	unsigned int validity_secs;

	/* Hash of From/To addresses normalized */
	const char *from_to_normalized_hash;
	/* Hash algorithm, which is used */
	enum coi_hash_algo hash_algo;

	/* Optional parameters, which we currently don't understand */
	ARRAY(struct coi_token_option) options;
};
ARRAY_DEFINE_TYPE(coi_token, struct coi_token *);

struct coi_contact {
	struct mail *mail;

	/* If non-NULL, the contact mail has invalid token content and this
	   contains the error message. There may still be some valid tokens
	   though, which can be used. */
	const char *error;

	ARRAY_TYPE(coi_token) tokens_in;
	ARRAY_TYPE(coi_token) tokens_out;
};

struct coi_contact_update {
	pool_t pool;
	struct mailbox *box;
	/* NOTE: contact.mail is NULL when creating a new contact */
	struct coi_contact contact;

	/* Non-NULL when creating a new contact */
	const char *create_from_normalized;

	bool changed;
	bool failed;
};

/* Generate a hash from normalized addresses. */
const char *
coi_contact_generate_hash(const char *from_normalized,
			  const char *to_normalized);

/* Allocate a new empty token and initialize it with minimal fields. */
struct coi_token *coi_token_new(pool_t pool);

/* Parse token string. Returns 0 on success, -1 on error. */
int coi_token_parse(const char *token_string, pool_t pool,
		    struct coi_token **token_r, const char **error_r);

/* Parse contact information from the given mail. Returns 0 on success, -1 on
   error accessing the mail. If the contact mail has invalid content, it's
   pointed out in the returned struct, but success is still returned.
   The contact is stored in the mail itself, so it gets freed when the mail
   gets freed. Multiple calls to this function returns the same cached
   contact. */
int coi_contact_parse(struct mail *mail, struct coi_contact **contact_r);

/* Append token to the string. */
void coi_token_append(string_t *dest, const struct coi_token *token);

/* Find the given token from the contact. */
struct coi_token *
coi_contact_token_in_find(struct coi_contact *contact, const char *token);
/* Find the given hash from the contact. If there are multiple, the newest
   one is returned. */
struct coi_token *
coi_contact_token_in_find_hash(struct coi_contact *contact, const char *hash);
struct coi_token *
coi_contact_token_out_find_hash(struct coi_contact *contact, const char *hash);

/* Update tokens in the contact. This can be thought of as a transaction,
   although it's not fully safe against conflicting updates. However, if there
   are two updates done simultaneously, coi-contact-list merges the changes
   as well as it can (but may cause e.g. deleted tokens to become undeleted).

   The update is finished by calling coi_contact_list_update().
*/
struct coi_contact_update *coi_contact_update_begin(struct mail *mail);
/* Create a new contact */
struct coi_contact_update *
coi_contact_create_begin(struct mailbox *box, const char *from_hash);
/* Add/replace token. The token is expected to have valid content. Invalid
   content may assert-crash. */
void coi_contact_update_add_token_in(struct coi_contact_update *update,
				     const struct coi_token *token);
void coi_contact_update_add_token_out(struct coi_contact_update *update,
				      const struct coi_token *token);
/* Delete token */
void coi_contact_update_delete(struct coi_contact_update *update,
			       const char *token);
/* Try to merge an old mail into this new mail. If there are any errors,
   the merging is simply not done. After successfully writing the new mail
   the old mail is expunged. */
void coi_contact_update_try_merge(struct coi_contact_update *update,
				  const struct coi_contact *old_contact);
/* Abort the update. */
void coi_contact_update_abort(struct coi_contact_update **update);

bool coi_token_verify_quick(const struct coi_secret_settings *set, time_t now,
			    const struct coi_token *token, bool *temp_r,
			    const char **error_r);

#endif
