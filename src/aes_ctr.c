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
#include "aes_ctr.h"


/* -------------------------------------------------------------------------- */
void aes_ctr_init(aes_ctr_context *ctx, uint8_t *key, uint8_t *iblk, uint8_t mode)
{
	uint8_t i, *p = (uint8_t *) &ctx->blk;

	if (!ctx)return;

	aes_set_key(&ctx->aes_ctx, key, 128);
	ctx->mode = mode;

	if (!iblk) return;

	for (i = 0; i < sizeof(ctx->blk); i++) p[i] = iblk[i];
}

/* -------------------------------------------------------------------------- */
static void ctr_inc_ctr(union ctr_blk_s *blk, int mode)
{
	int i, len;
	uint8_t *val;

	if (mode & 0x10) {
		val = blk->rfc3686.ctr;
		len = 4;
	} else {
		val = blk->ctr;
		len = 16;
	}

	if ((mode & 0x01) == CTR_LITTLE_ENDIAN) {
		for (i = 0; i < len; i++) if (++(val[i]) != 0) break;
	} else {
		for (i = len-1; i >= 0; i--) if (++(val[i]) != 0) break;
	}

	return;
}

/* -------------------------------------------------------------------------- */
static void ctr_clock_keystream(aes_ctr_context *ctx, uint8_t *ks)
{
	uint8_t i;
	uint8_t *p = (uint8_t *) &ctx->blk;

	for (i = 0; i < sizeof(ctx->blk); i++) ks[i] = p[i];

	aes_encrypt(&ctx->aes_ctx, ks, ks);
	ctr_inc_ctr(&ctx->blk, ctx->mode);
}

/* -------------------------------------------------------------------------- */
void aes_ctr_encrypt(aes_ctr_context *ctx, uint8_t *data, size_t sz)
{
	uint8_t key[sizeof(ctx->blk)];
	size_t  i;
	uint8_t j = sizeof(key);

	for (i = 0; i < sz; i++) {
		if ( j == sizeof(key) ) {
			j = 0;
			ctr_clock_keystream(ctx, key);
		}
		data[i] ^= key[j++];
	}

} /* aes256_encrypt_ctr */
