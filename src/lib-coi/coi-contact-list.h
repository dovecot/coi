#ifndef COI_CONTACT_LIST_H
#define COI_CONTACT_LIST_H

struct mailbox;
struct coi_token;
struct coi_contact;
struct coi_contact_update;

struct coi_contact_list *coi_contact_list_init_mailbox(struct mailbox *box);
void coi_contact_list_deinit(struct coi_contact_list **list);

struct coi_contact_transaction *
coi_contact_transaction_begin(struct coi_contact_list *list);
void coi_contact_transaction_commit(struct coi_contact_transaction **trans);

struct mailbox *
coi_contact_transaction_get_mailbox(struct coi_contact_transaction *trans);

/* Find the contact mail for given from/to pair. Duplicate mails are handled
   internally, so only a single mail is returned. Returns 0 and contact_r on
   success, 0 and contact_r=NULL if not found, -1 and error_storage_r on
   failure. The storage can be used to access the error message. */
int coi_contact_list_find(struct coi_contact_transaction *trans,
			  const char *from_normalized,
			  const char *to_normalized,
			  struct coi_contact **contact_r,
			  struct mail_storage **error_storage_r);
/* Find the contact mail for given from/to pair that also has the given token.
   This may be more optimized than just looking for the from/to pair. Returns
   1 if token is currently valid, 0 if token wasn't found or was expired,
   -1 and error_storage_r on failure. The storage can be used to access the
   error message. When 1 or 0 is returned, also contact_r and token_r are
   returned. If the token didn't exist, it's NULL. The returned contact must
   be freed with mail_free(contact->mail) */
int coi_contact_list_find_token(struct coi_contact_transaction *trans,
				const char *from_normalized,
				const char *to_normalized,
				const char *token, time_t timestamp,
				struct coi_contact **contact_r,
				struct coi_token **token_r,
				struct mail_storage **error_storage_r);

/* Update contact mail. Returns 0 on succes, -1 and error_storage_r on error.
   The storage can be used to access the error message. */
int coi_contact_list_update(struct coi_contact_transaction **trans,
			    struct coi_contact_update **update,
			    struct mail_storage **error_storage_r);

#endif
