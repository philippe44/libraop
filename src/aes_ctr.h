/*
*   Byte-oriented AES-256 implementation.
*   All lookup tables replaced with 'on the fly' calculations.
*
*   Copyright (c) 2007-2009 Ilya O. Levin, http://www.literatecode.com
*   Other contributors: Hal Finney
*   AES128 support (c) 2013 Paul Sokolovsky
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#ifndef uint8_t
#include <stdint.h>
#endif
#ifndef size_t
#include <stddef.h>
#endif

#include "aes.h"

#define CTR_LITTLE_ENDIAN			0x00
#define CTR_BIG_ENDIAN				0x01
#define CTR_RFC3686_LITTLE_ENDIAN	0x10
#define CTR_RFC3686_BIG_ENDIAN		0x11

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct {
		union ctr_blk_s {
				uint8_t ctr[16];
				struct {
					uint8_t nonce[4];
					uint8_t iv[8];
					uint8_t ctr[4];
				} rfc3686;
		} blk;
		int mode;
		aes_context aes_ctx;
	} aes_ctr_context;


	void aes_ctr_init(aes_ctr_context *ctx, uint8_t *key, uint8_t *iv, uint8_t mode);
	void aes_ctr_encrypt(aes_ctr_context *ctx, uint8_t *data, size_t sz);
	#define aes_ctr_decrypt(ctx, data, sz) aes_ctr_encrypt(ctx, data, sz);

#ifdef __cplusplus
}
#endif
