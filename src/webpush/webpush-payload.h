#ifndef WEBPUSH_PAYLOAD_H
#define WEBPUSH_PAYLOAD_H 1

enum webpush_payload_encryption_type {
	PAYLOAD_ENCRYPTION_TYPE_AESGCM = 1,
	PAYLOAD_ENCRYPTION_TYPE_AES128GCM = 2,
};

/* Encrypts payload to given subscription

   - plaintext - plaintext to cipher
   - padding - number of padding bytes to add
   - ephemeral_key_r - X9.26 encoded ephemeral key
   - salt_r - used salt (should be passed to recipient)
   - encrypted_r - encrypted text and GCM tag
*/
int webpush_payload_encrypt(const struct webpush_subscription *subscription,
			    enum webpush_payload_encryption_type enc_type,
			    const buffer_t *plaintext, uint16_t padding,
			    buffer_t *ephemeral_key_r, buffer_t *salt_r,
			    buffer_t *encrypted_r, const char **error_r);

/* Creates auth header for payload
 - payload - JWT body
 - key - vapid private key
 - b64_token_r - JWT token in base64
 - b64_key_r - public vapid key in JWK format for the JWT
*/
int webpush_payload_sign(const buffer_t *payload, struct dcrypt_private_key *key,
			 string_t *b64_token_r, string_t *b64_key_r,
			 const char **error_r);

#endif
