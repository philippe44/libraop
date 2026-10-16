/*
 * Minimal libsodium compatibility layer for pair_ap, implemented with OpenSSL
 *
 * libsodium ed25519 secret keys are seed (32) || public key (32), OpenSSL
 * only wants the seed, so conversions are done here.
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "sodium.h"

/*----------------------------------------------------------------------------*/
int sodium_init(void) {
	return 0;
}

/*----------------------------------------------------------------------------*/
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed) {
	EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, crypto_sign_SEEDBYTES);
	size_t len = crypto_sign_PUBLICKEYBYTES;
	int rc = -1;

	if (key && EVP_PKEY_get_raw_public_key(key, pk, &len) == 1) {
		memcpy(sk, seed, crypto_sign_SEEDBYTES);
		memcpy(sk + crypto_sign_SEEDBYTES, pk, crypto_sign_PUBLICKEYBYTES);
		rc = 0;
	}

	EVP_PKEY_free(key);
	return rc;
}

/*----------------------------------------------------------------------------*/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
	unsigned char seed[crypto_sign_SEEDBYTES];

	if (RAND_bytes(seed, sizeof(seed)) != 1) return -1;
	return crypto_sign_seed_keypair(pk, sk, seed);
}

/*----------------------------------------------------------------------------*/
int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p, const unsigned char *m,
						 unsigned long long mlen, const unsigned char *sk) {
	EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, crypto_sign_SEEDBYTES);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	size_t len = crypto_sign_BYTES;
	int rc = -1;

	if (key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
		EVP_DigestSign(ctx, sig, &len, m, mlen) == 1) {
		if (siglen_p) *siglen_p = len;
		rc = 0;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return rc;
}

/*----------------------------------------------------------------------------*/
int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
								unsigned long long mlen, const unsigned char *pk) {
	EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, crypto_sign_PUBLICKEYBYTES);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int rc = -1;

	if (key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
		EVP_DigestVerify(ctx, sig, crypto_sign_BYTES, m, mlen) == 1) rc = 0;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return rc;
}

/*----------------------------------------------------------------------------*/
int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk) {
	memcpy(pk, sk + crypto_sign_SEEDBYTES, crypto_sign_PUBLICKEYBYTES);
	return 0;
}

/*----------------------------------------------------------------------------*/
int crypto_box_keypair(unsigned char *pk, unsigned char *sk) {
	EVP_PKEY *key;
	size_t len = crypto_box_PUBLICKEYBYTES;
	int rc = -1;

	if (RAND_bytes(sk, crypto_box_SECRETKEYBYTES) != 1) return -1;

	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, crypto_box_SECRETKEYBYTES);
	if (key && EVP_PKEY_get_raw_public_key(key, pk, &len) == 1) rc = 0;

	EVP_PKEY_free(key);
	return rc;
}

/*----------------------------------------------------------------------------*/
int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
	EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, n, crypto_scalarmult_SCALARBYTES);
	EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, p, crypto_scalarmult_BYTES);
	EVP_PKEY_CTX *ctx = priv ? EVP_PKEY_CTX_new(priv, NULL) : NULL;
	size_t len = crypto_scalarmult_BYTES;
	int rc = -1;

	if (priv && peer && ctx && EVP_PKEY_derive_init(ctx) == 1 &&
		EVP_PKEY_derive_set_peer(ctx, peer) == 1 && EVP_PKEY_derive(ctx, q, &len) == 1) rc = 0;

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);
	EVP_PKEY_free(priv);
	return rc;
}
