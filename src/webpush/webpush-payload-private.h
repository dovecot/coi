#ifndef WEBPUSH_PAYLOAD_PRIVATE_H
#define WEBPUSH_PAYLOAD_PRIVATE_H 1

#define JWT_HASH "sha256"
#define JWT_SIGN_HEADER "{\"typ\":\"JWT\",\"alg\":\"ES256\"}"

#define WEBPUSH_CURVE "prime256v1"
#define WEBPUSH_HASH "sha256"

#define WEBPUSH_SALT_LEN 16

/* Pad data to given padding length */
buffer_t *webpush_payload_pad_data(enum webpush_payload_encryption_type enc_type,
				   const buffer_t *plaintext, uint16_t pad_len);

/* Calculates key and nonce from given input values */
void webpush_payload_calculate_key_nonce(enum webpush_payload_encryption_type enc_type,
					 const buffer_t *client_key,
					 const buffer_t *server_key,
					 const buffer_t *auth_data,
					 const buffer_t *S,
					 const buffer_t *salt,
					 buffer_t *key_r,
					 buffer_t *nonce_r);
#endif
