/*****************************************************************************
 * rtsp_client.h: RAOP Client
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 *				 2016 Philippe <philippe_44@outlook.com>
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
 
#ifndef __RAOP_CLIENT_H_
#define __RAOP_CLIENT_H_

/*--------------- SYNCHRO logic explanation ----------------*/
/* The logic is that, using one user-provided function
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

 The player also have a queue to absord network jitter (this has nothing to do
 with the latency). The function raopcl_avail_frames() return the amount of free
 frames in the buffer.

 There are two ways to calculate the duration of what has been played
 1- Based on time: if pause has never been made, simply make the difference
 between the NTP start time and the current NTP time, minus the latency (in NTP)
 2- Based on sent frames: this is the only reliable method if pause has been
 used ==> substracts raopcl_queue_len() and raopcl_latency() to the number of
 frames. Any other method based on taking local time at pause and substracting
 local paused tme is not as accurate.


 // to be revised


  With that, the user app can be sure that when it wants to
 play/do something at its local gettime_ms(), the player will do it at the exact
 same time plus the latency. Both references and synchronous. The desired latency
 is set when creating the player using raoplc_create(). When connecting, players
 return their minimum latency so the real value might be above the desired value
 Use raop_get_latency() to retrieve the used one.

 Because it's needed to send data in advance (buffering), the user app shall use
 raopcl_avail_frames and raopcl_queue_len() to evaluate the empty/fullness of
 the buffer, not try to guess it (see why below)

 Send frames by calling raopcl_send_chunk() after having encoded them in ALAC
 using pcm_to_alac()

 To know, in gettime() reference, how long of the current song has been played
 count the frames sent to the player since the last flush, substract what's in
 the queue using raopl_queue_len() and then substract the latency

 Continue sending frames whenever raopcl_avail_frames() does not return 0. When
 0 is return, wait (sleep) a bit before trying again (sleeping is better to save
 CPU, although it's not mandatory, just don't call raopcl_send_chunk() when
 there is no space)

 To start at a precise time, just use raopcl_set_start() after having flushed
 the player and give the desired start time in local gettime() time. The latency
 will be substracted from that time to make sure the player starts exactly when
 required. Then do as usual using raopcl_avail_frames() and raoplc_send_chunk()
 to send frames and evaluate queue fullness. Note that until the first call to
 raopcl_send_chunk(), queue will always appear to be full

 To pause call raopcl_pause_mode(), flush the player and stop sending data. Play
 will resume as soon as a call to raopcl_send_chunk() is made (unless a specific
 start time has been set). It is not possible to pause at a given time
*/

#include "platform.h"

#define MAX_SAMPLES_PER_CHUNK 352
#define RAOP_LATENCY_MIN 11025

#define NTP2MS(ntp) ((((ntp) >> 10) * 1000L) >> 22)
#define MS2NTP(ms) (((((__u64) (ms)) << 22) / 1000) << 10)
#define TIME_MS2NTP(time) raopcl_time32_to_ntp(time)
#define NTP2TS(ntp, rate) ((((ntp) >> 16) * (rate)) >> 16)
#define TS2NTP(ts, rate)  (((((__u64) (ts)) << 16) / (rate)) << 16)
#define MS2TS(ms, rate) ((((__u64) (ms)) * (rate)) / 1000)
#define TS2MS(ts, rate) NTP2MS(TS2NTP(ts,rate))

typedef struct raopcl_t {__u32 dummy;} raopcl_t;

struct raopcl_s;

typedef enum raop_codec_s { RAOP_NOCODEC = -1, RAOP_PCM = 0, RAOP_ALAC, RAOP_AAC,
							RAOP_AAL_ELC } raop_codec_t;

typedef enum raop_crypto_s { RAOP_CLEAR = 0, RAOP_RSA, RAOP_FAIRPLAY, RAOP_MFISAP,
							RAOP_FAIRPLAYSAP } raop_crypto_t;

typedef enum raop_states_s { RAOP_DOWN_FULL = 0, RAOP_PEER_DISCONNECT, RAOP_DOWN,
							 RAOP_FLUSHING, RAOP_FLUSHED, RAOP_STREAMING } raop_state_t;

typedef struct {
	int channels;
	int	sample_size;
	int	sample_rate;
	raop_codec_t codec;
	raop_crypto_t crypto;
} raop_settings_t;

typedef struct {
	__u8 proto;
	__u8 type;
	__u8 seq[2];
#if WIN
} rtp_header_t;
#else
} __attribute__ ((packed)) rtp_header_t;
#endif

typedef struct {
	rtp_header_t hdr;
	__u32 	rtp_timestamp_latency;
	ntp_t   curr_time;
	__u32   rtp_timestamp;
#if WIN
} rtp_sync_pkt_t;
#else
} __attribute__ ((packed)) rtp_sync_pkt_t;
#endif

typedef struct {
	rtp_header_t hdr;
	__u32 timestamp;
	__u32 ssrc;
#if WIN
} rtp_audio_pkt_t;
#else
} __attribute__ ((packed)) rtp_audio_pkt_t;
#endif

struct raopcl_s *raopcl_create(char *local, char *DACP_id, char *active_remote,
							   raop_codec_t codec, int frame_len, int queue_len,
							   int latency_frames, raop_crypto_t crypto,
							   int sample_rate, int sample_size, int channels, int volume);
bool	raopcl_destroy(struct raopcl_s *p);
bool	raopcl_connect(struct raopcl_s *p, struct in_addr host, __u16 destport, raop_codec_t codec);
bool 	raopcl_reconnect(struct raopcl_s *p);
bool 	raopcl_disconnect(struct raopcl_s *p);
bool 	raopcl_teardown(struct raopcl_s *p);
bool 	raopcl_close(struct raopcl_s *p);
bool 	raopcl_sanitize(struct raopcl_s *p);

bool    raopcl_flush(struct raopcl_s *p);
bool 	raopcl_start_at(struct raopcl_s *p, __u64 start_time);
void 	raopcl_pause(struct raopcl_s *p);
void 	raopcl_stop(struct raopcl_s *p);

__u32 	raopcl_accept_frames(struct raopcl_s *p);
__u32 	raopcl_queued_frames(struct raopcl_s *p);
bool	raopcl_send_chunk(struct raopcl_s *p, __u8 *sample, int size, __u64 *playtime);

__u32 	raopcl_latency(struct raopcl_s *p);
__u32 	raopcl_sample_rate(struct raopcl_s *p);
raop_state_t raopcl_state(struct raopcl_s *p);
__u32 	raopcl_queue_len(struct raopcl_s *p);

bool 	raopcl_is_sane(struct raopcl_s *p);
bool 	raopcl_is_connected(struct raopcl_s *p);

bool 	raopcl_set_content(raopcl_t *p, char* itemname, char* songartist, char* songalbum);
bool 	raopcl_set_progress(struct raopcl_s *p, __u64 elapsed, __u64 end);
bool 	raopcl_set_progress_ms(struct raopcl_s *p, __u32 elapsed, __u32 duration);
bool 	raopcl_set_volume(struct raopcl_s *p, int vol, bool force);
bool 	raopcl_set_daap(struct raopcl_s *p, int count, ...);
bool 	raopcl_set_artwork(struct raopcl_s *p, char *content_type, int size, char *image);

__u64 	raopcl_time32_to_ntp(__u32 time);

#endif
