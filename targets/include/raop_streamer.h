/*
 * RAOP: streamer interface
 *
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 *
 */

#pragma once

#include "cross_util.h"

typedef struct {
	unsigned short cport, tport, aport, hport;
	struct raopst_s *ctx;
} raopst_resp_t;

typedef struct {
	enum { CODEC_MP3 = 0, CODEC_FLAC, CODEC_PCM, CODEC_WAV} codec;
	union {
		struct {
			int bitrate;
			bool icy;
		} mp3;
		struct {
			int level;
		} flac;
	};
} raopst_encode_t;

typedef enum { RAOP_STREAMER_PLAY } raopst_event_t;

typedef	void (*event_cb_t)(void *owner, raopst_event_t event);
typedef void (*http_cb_t)(void *owner, struct key_data_s *headers, struct key_data_s *response);

raopst_resp_t 	raopst_init(struct in_addr host, struct in_addr peer, raopst_encode_t codec,
							bool sync, bool drift, bool range, char *latencies,
							char *aeskey, char *aesiv, char *fmtpstr,
							short unsigned pCtrlPort, short unsigned pTimingPort,
							void *owner, event_cb_t event_cb, http_cb_t http_cb,
							unsigned short port_base, unsigned short port_range,
							int http_length);
void			 	raopst_end(struct raopst_s *ctx);
bool 				raopst_flush(struct raopst_s *ctx, unsigned short seqno, unsigned rtptime, bool exit_locked, bool silence);
void 				raopst_flush_release(struct raopst_s *ctx);
void 				raopst_record(struct raopst_s *ctx, unsigned short seqno, unsigned rtptime);
void 				raopst_metadata(struct raopst_s *ctx, struct raopsv_metadata_s *metadata);
