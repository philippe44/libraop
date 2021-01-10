/*****************************************************************************
 * audio_stream.h: audio file stream, header file
 *
 * Copyright (C) 2016 Philippe <philippe44@outlook.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/
#ifndef __ALAC_WRAPPER_H_
#define __ALAC_WRAPPER_H_

struct alac_codec_s;

#ifdef __cplusplus
extern "C" {
#endif

struct alac_codec_s *alac_create_decoder(int magic_cookie_size, uint8_t *magic_cookie,
								uint8_t *sample_size, unsigned *sample_rate,
								uint8_t *channels, unsigned int *block_size);
void alac_delete_decoder(struct alac_codec_s *codec);
bool alac_to_pcm(struct alac_codec_s *codec, uint8_t* input,
				 uint8_t *output, char channels, unsigned *out_frames);

bool pcm_to_alac(struct alac_codec_s *codec, uint8_t *in, int frames, uint8_t **out, int *size);
bool pcm_to_alac_raw(uint8_t *in, int frames, uint8_t **out, int *size, int bsize);
struct alac_codec_s *alac_create_encoder(int chunk_len, int sampleRate, int sampleSize, int channels);
void alac_delete_encoder(struct alac_codec_s *codec);
#ifdef __cplusplus
}
#endif

#endif
