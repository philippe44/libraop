/*
 * RAOP : Client to control an AirPlay device, RAOP part
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 *
 */
 
#ifndef __RAOP_CLIENT_H_
#define __RAOP_CLIENT_H_

/*--------------- SYNCHRO logic explanation ----------------*/

/*
 The logic is that, using one user-provided function
 - get_ntp(struct ntp_t *) returns a NTP time as a flat 64 bits value and in the
 structure passed (if NULL, just return the value)

 The RAOP client automatically binds the NTP time of the player to the NTP time
 provided by get_ntp. RAOP players measure also audio with timestamps, one per
 frame (sample = 44100 per seconds normally). There are few macros to move from
 NTP to TS values.

 RAOP players have a latency which is usually 11025 frames. It's possible to set
 another value at the player creation, but always use the raopcl_latency()
 accessor to obtain the real value - in frames.

 The precise time at the DAC is the time at the client plus the latency, so when
 setting a start time, we must anticipate by the latency if we want the first
 frame to be *exactly* played at that NTP value.

 There are two ways to calculate the duration of what has been played
 1- Based on time: if pause has never been made, simply make the difference
 between the NTP start time and the current NTP time, minus the latency (in NTP)
 2- Based on sent frames: this is the only reliable method if pause has been
 used ==> substract raopcl_latency() to the number of frames sent . Any other
 method based on taking local time at pause and substracting local paused tme is
 not as accurate.
 */

 /*--------------- USAGE ----------------*/

 /*
 To play, call raopcl_accept_frames. When true is return, one frame can be sent,
 so just use raopcl_send_chunk - ONE AT A TIME. The pacing is handled by the
 calls to raopcl_accept_frames. To send in burst, send at least raopcl_latency
 frames, sleep a while and then do as before

 To start at a precise time, just use raopcl_set_start() after having flushed
 the player and give the desired start time in local gettime() time, minus
 latency.

 To pause, stop calling raopcl_accept_frames and raopcl_send_chunk (obviously),
 call raopcl_pause then raopcl_flush. To stop call raopcl_stop instead of
 raopcl_pause

 To resume, optionally call raopcl_set_start to restart at a given time or just
 start calling raopcl_accept_frames and send raopcl_send_chunk
*/

#include "platform.h"

#define MAX_SAMPLES_PER_CHUNK 	352
#define RAOP_LATENCY_MIN 		11025
#define SECRET_SIZE				64

typedef struct ntp_s {
	uint32_t seconds;
	uint32_t fraction;
} ntp_t;

#define NTP2MS(ntp) ((((ntp) >> 10) * 1000L) >> 22)
#define MS2NTP(ms) (((((uint64_t) (ms)) << 22) / 1000) << 10)
#define TIME_MS2NTP(time) raopcl_time32_to_ntp(time)
#define NTP2TS(ntp, rate) ((((ntp) >> 16) * (rate)) >> 16)
#define TS2NTP(ts, rate)  (((((uint64_t) (ts)) << 16) / (rate)) << 16)
#define MS2TS(ms, rate) ((((uint64_t) (ms)) * (rate)) / 1000)
#define TS2MS(ts, rate) NTP2MS(TS2NTP(ts,rate))

typedef struct raopcl_t {uint32_t dummy;} raopcl_t;

struct raopcl_s;

typedef enum raop_codec_s { RAOP_PCM = 0, RAOP_ALAC_RAW, RAOP_ALAC, RAOP_AAC,
							RAOP_AAL_ELC } raop_codec_t;
typedef enum raop_crypto_s { RAOP_CLEAR = 0, RAOP_RSA, RAOP_FAIRPLAY, RAOP_MFISAP,
							 RAOP_FAIRPLAYSAP } raop_crypto_t;
typedef enum raop_states_s { RAOP_DOWN = 0, RAOP_FLUSHING, RAOP_FLUSHED,
							 RAOP_STREAMING } raop_state_t;

typedef struct {
	int channels;
	int	sample_size;
	int	sample_rate;
	raop_codec_t codec;
	raop_crypto_t crypto;
} raop_settings_t;

typedef struct {
	uint8_t proto;
	uint8_t type;
	uint8_t seq[2];
} __attribute__ ((packed)) rtp_header_t;

typedef struct {
	rtp_header_t hdr;
	uint32_t 	rtp_timestamp_latency;
	ntp_t   curr_time;
	uint32_t   rtp_timestamp;
} __attribute__ ((packed)) rtp_sync_pkt_t;

typedef struct {
	rtp_header_t hdr;
	uint32_t timestamp;
	uint32_t ssrc;
} __attribute__ ((packed)) rtp_audio_pkt_t;

uint64_t raopcl_get_ntp(struct ntp_s* ntp);

// if volume < -30 and not -144 or volume > 0, then not "initial set volume" will be done
struct raopcl_s *raopcl_create(struct in_addr host, uint16_t port_base, uint16_t port_range,
							   char *DACP_id, char *active_remote,
							   raop_codec_t codec, int frame_len, int latency_frames,
							   raop_crypto_t crypto, bool auth, char *secret,
							   char *et, char *md,
							   int sample_rate, int sample_size, int channels, float volume);

bool	raopcl_destroy(struct raopcl_s *p);
bool	raopcl_connect(struct raopcl_s *p, struct in_addr host, uint16_t destport, bool set_volume);
bool 	raopcl_repair(struct raopcl_s *p, bool set_volume);
bool 	raopcl_disconnect(struct raopcl_s *p);
bool    raopcl_flush(struct raopcl_s *p);
bool 	raopcl_keepalive(struct raopcl_s *p);

bool 	 raopcl_set_progress(struct raopcl_s *p, uint64_t elapsed, uint64_t end);
bool 	 raopcl_set_progress_ms(struct raopcl_s *p, uint32_t elapsed, uint32_t duration);
uint64_t raopcl_get_progress_ms(struct raopcl_s* p);
bool 	 raopcl_set_volume(struct raopcl_s *p, float vol);
float 	 raopcl_float_volume(int vol);
bool 	 raopcl_set_daap(struct raopcl_s *p, int count, ...);
bool 	 raopcl_set_artwork(struct raopcl_s *p, char *content_type, int size, char *image);

bool 	raopcl_accept_frames(struct raopcl_s *p);
bool	raopcl_send_chunk(struct raopcl_s *p, uint8_t *sample, int size, uint64_t *playtime);

bool 	raopcl_start_at(struct raopcl_s *p, uint64_t start_time);
void 	raopcl_pause(struct raopcl_s *p);
void 	raopcl_stop(struct raopcl_s *p);

/*
	These are thread safe
*/
uint32_t 	raopcl_latency(struct raopcl_s *p);
uint32_t 	raopcl_sample_rate(struct raopcl_s *p);
raop_state_t raopcl_state(struct raopcl_s *p);
uint32_t 	raopcl_queue_len(struct raopcl_s *p);

uint32_t 	raopcl_queued_frames(struct raopcl_s *p);

bool 	raopcl_is_sane(struct raopcl_s *p);
bool 	raopcl_is_connected(struct raopcl_s *p);
bool 	raopcl_is_playing(struct raopcl_s *p);
bool 	raopcl_sanitize(struct raopcl_s *p);

uint64_t 	raopcl_time32_to_ntp(uint32_t time);

struct mdnssd_handle_s;

bool AppleTVpairing(struct mdnssd_handle_s* mDNShandle, char** pUDN, char** pSecret);

#endif
