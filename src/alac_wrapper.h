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

bool pcm_to_alac(struct alac_codec_s *codec, __u8 *in, int frames, __u8 **out, int *size);
bool pcm_to_alac_fast(__u8 *in, int frames, __u8 **out, int *size, int bsize);
struct alac_codec_s *alac_create_codec(int chunk_len, int sampleRate, int sampleSize, int channels);
void alac_destroy_codec(struct alac_codec_s *codec);
#ifdef __cplusplus
}
#endif

#endif
