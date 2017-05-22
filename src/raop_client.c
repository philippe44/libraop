/*****************************************************************************
 * rtsp_client.c: RAOP Client
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
#include <stdio.h>
#include "platform.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include <pthread.h>
#include <semaphore.h>

#include <time.h>
#include <stdlib.h>

#include <limits.h>
#include "alac_wrapper.h"
#include "aexcl_lib.h"
#include "rtsp_client.h"
#include "raop_client.h"
#include "base64.h"
#include "aes.h"

#define MAX_BACKLOG 512

#define JACK_STATUS_DISCONNECTED 0
#define JACK_STATUS_CONNECTED 1

#define JACK_TYPE_ANALOG 0
#define JACK_TYPE_DIGITAL 1

#define VOLUME_MIN -30
#define VOLUME_MAX 0

#define SEC(ntp) ((__u32) ((ntp) >> 32))
#define FRAC(ntp) ((__u32) (ntp))
#define SECNTP(ntp) SEC(ntp),FRAC(ntp)
#define MSEC(ntp)  ((__u32) ((((ntp) >> 16)*1000) >> 16))

/*
 --- timestamps (ts), millisecond (ms) and network time protocol (ntp) ---
 NTP is starting Jan 1900 (EPOCH) made of 32 high bits (seconds) and 32
 low bits (fraction).
 The player needs timestamp that increment by one for every sample (44100/s), so
 we created a "absolute" timestamp that is direcly based on NTP: it has the same
 "origin" for time.
	- TS = NTP * sample_rate / 2^32 (TS fits in 64bits no matter what)
	- NTP = TS * 2^32 / sample_rate
 Because sample_rate is less than 16 bits, then TS always have the highest 16
 bits available, so this gives, with proper rounding and avoiding overflow:
	- TS  = ((NTP >> 16) * sample_rate) >> 16
	- NTP = ((TS << 16) / sample_rate) << 16
 If we want to use a more convenient millisecond base, it must be derived from
 the same NTP and if we want to use only a 32 bits value, raopcl_time32_to_ntp()
 do the "guess" of a 32 bits ms counter into a proper NTP

 --- head_ts and offset_ts ---
 The head_ts value indicates the absolute frame number of the most recent frame
 in the player queue. When starting to play without a special start time, we
 assume that we want to start at the closed opportunity, so by setting the
 head_ts to the current absolute_ts (called now_ts), we are sure that the player
 will start to play the first frame at now_ts + latency, which means it has time
 to process a frame send with now_ts timestamp. We could further optimize that
 by reducing a bit this value
 To handle network jitter, there is a queue in the player, so frames can be sent
 ahead of current absolute ts. This means that the most recently sent frame has
 a head_ts which is at maximum now_ts + queue_len
 The offset_ts is required to handle flushing properly. Players do not accept
 frames with timestamps that have already been used, timestamps must always
 increment. When sending the 1st frame after a flush, the head_ts is normally
 reset to now_ts, but because such frame number might already have been sent due
 to buffering, we cannot reset the head_ts, it must continue where it is. This
 gap is offset_ts = head_ts(at restart) - now_ts
 But that new timestamp is ahead of the earlies "absolute TS", so to make sure
 these new "offset" frames are sent with the same latency than the others, the
 synchro between NTP and TS must alos be offset by that value
 None of this needs to be done if now_ts is above head_ts when starting playback
 after flushing, head_ts can simply be reset to now_ts and synchronization does
 not need to be offset any more

 --- latency ---
 AirPlay devices seem to send everything with a latency of 11025 + the latency
 set in the sync packet, no matter what.

 --- start time ---
 As explained in the header of this file, the caller of raopcl_set_start() must
 anticipate by raopcl_latency() if he wants the next frame to be played exactly
 at a given NTP time

 --- queuing & pause ---
  A small example to explain how pause and the whole thing works. Everything
  expressed in frames timestamp format
  Say that latency is 10 frames, the queue size is 100 frames and we want to
  start at t=2000, assuming now=1000
  Say that the player will want to pause at t=2200 and resume at t=2500
  "avail()" means calls to raopcl_space_frames() and we assume that buffer fill
  takes no time.
  cons = now_ts - first_ts or 0 if negative
  total = head_ts - first_ts

  - Call raopcl_set_start with 2000-10=1990. This sets the start_ts at 1990
  - When a call to raopcl_accept_frames is made it sets head_ts and first_ts to
	1990 (the start_ts)
  - At t=1000 avail is 100 as cons=0, total=1990-1990=0
  - Buffer fill starts and when head_ts=2090, avail returns zero and no further
	frames can be filled
  - At this point, the client has provided 100 frames the head_ts has been
	incremented is now 2090 (+100) - this will stay like that till t=2000
  - At t=2000 cons=2000-1990=10, total=2090-1990=100, avail is 10 so the client
	sends another 10 frames, the sum of supplied frames is 110 and head_ts is
	now 2100. This happened just AFTER t=2000
  - To calculate the number of frames already *heard*, the client must use what
	he has sent (110), minus what is in the buffer using raopcl_queued_frames()
	(100), minus the latency (10) so at t=2000, 0 frames have been heard!
  - At t=2001, cons=2001-1990=11, total=2100-1990=110, so avail=100-(110-11)=1
	The cLient fills one frame so it has sent 111 frames and 111-100-10=1 frames
	has been heard. The value of head_ts is 2101
  - At t=2200, right after filling frames, cons=2200-1990=210,
	total=2300-1990=310, so avail=100-(310-210)=0, the client has provided
	another 200 frames, so 310 in total (head_ts is 2300)
  - At this point, the client decides to stop and call raopcl_set_pause(). That
	sets pause_ts at head_ts, so 2300.
  -	Client must absolutely *not* call raopcl_send_chunk() and must call
	raopcl_flush() to mute audio. Calls to raopcl_accept_frames returns 0 to
	block any further attemp to send frames.
  - Any further call to raopcl_queued_frames avail will use pause_ts, so the
	size of the queue is frozen, as expected. When calculating what has been
	heard, client does 310(sent)-100(queue)-10(latency)=200 which is correct
  - At t=2400, the client decides to set resume at 2500, so it expects that the
	1st frame to be played, will be at 2500 precisely and that frame will the
	201th frames BECAUSE ONLY 200 AS BEEN PLAYED SO FAR
  - As it should, the client calls raopcl_set_start with 2500-10=2490. That sets
	first_ts=start_ts=2490. The raopcl_accept_frames will remain stuck until
	flushing has been done or we are going closer than 2500-10
  - When flushing is done, say at t=2450, raopcl_accept_frames sets head_ts and
	first_ts to	2490, so cons=2350-2490=0, total=0, avail is still zero until
	ts=2491 is reached.
  - At frame 2491, cons=2491-2490=1, total=0, so avail=1, the client can send 1
	frame. Such frame will he heard in 2501, but this next frame is the 311th
	frame, so it would be played with 100+10+1 frames early.
  - ... so reality says 100+20-1, need to check why (and this is not platform
   dependent)

*/


// all the following must be 32-bits aligned

typedef struct {
	rtp_header_t hdr;
	__u32 dummy;
	ntp_t ref_time;
	ntp_t recv_time;
	ntp_t send_time;
#if WIN
} rtp_time_pkt_t;
#else
} __attribute__ ((packed)) rtp_time_pkt_t;
#endif

typedef struct {
	rtp_header_t hdr;
	__u16 seq_number;
	__u16 n;
#if WIN
} rtp_lost_pkt_t;
#else
} __attribute__ ((packed)) rtp_lost_pkt_t;
#endif

typedef struct raopcl_s {
	struct rtspcl_s *rtspcl;
	raop_state_t state;
	char DACP_id[17], active_remote[11];
	struct {
		unsigned int ctrl, time;
		struct { unsigned int avail, select, send; } audio;
	} sane;
	unsigned int retransmit;
	__u8 iv[16]; // initialization vector for aes-cbc
	__u8 nv[16]; // next vector for aes-cbc
	__u8 key[16]; // key for aes-cbc
	struct in_addr	host_addr, local_addr;
	__u16 rtsp_port;
	rtp_port_t	rtp_ports;
	struct {
		__u16 seq_number;
		__u64 timestamp;
		int	size;
		u8_t *buffer;
	} backlog[MAX_BACKLOG];
	// int ajstatus, ajtype;
	float volume;
	aes_context ctx;
	int size_in_aex;
	bool encrypt;
	bool first_pkt;
	__u64 head_ts, pause_ts, start_ts, first_ts;
	bool flushing;
	__u16   seq_number;
	unsigned long ssrc;
	__u32 latency_frames;
	int chunk_len;
	pthread_t time_thread, ctrl_thread;
	pthread_mutex_t mutex;
	bool time_running, ctrl_running;
	int sample_rate, sample_size, channels;
	raop_codec_t codec;
	struct alac_codec_s *alac_codec;
	raop_crypto_t crypto;
	bool auth;
} raopcl_data_t;


extern log_level	raop_loglevel;
static log_level 	*loglevel = &raop_loglevel;

static void 	*_rtp_timing_thread(void *args);
static void 	*_rtp_control_thread(void *args);
static void 	_raopcl_terminate_rtp(struct raopcl_s *p);
static void 	_raopcl_send_sync(struct raopcl_s *p, bool first);
static bool 	_raopcl_send_audio(struct raopcl_s *p, rtp_audio_pkt_t *packet, int size);
static bool 	_raopcl_disconnect(struct raopcl_s *p, bool force);

// a few accessors
/*----------------------------------------------------------------------------*/
raop_state_t raopcl_state(struct raopcl_s *p)
{
	if (!p) return RAOP_DOWN;

	return p->state;
}


/*----------------------------------------------------------------------------*/
__u32 raopcl_latency(struct raopcl_s *p)
{
	if (!p) return 0;

	// why do AirPlay devices use required latency + 11025 ???
	return p->latency_frames + RAOP_LATENCY_MIN;
}


/*----------------------------------------------------------------------------*/
__u32 raopcl_sample_rate(struct raopcl_s *p)
{
	if (!p) return 0;

	return p->sample_rate;
}


/*----------------------------------------------------------------------------*/
__u64 raopcl_time32_to_ntp(__u32 time)
{
	__u64 ntp_ms = ((get_ntp(NULL) >> 16) * 1000) >> 16;
	__u32 ms = (__u32) ntp_ms;
	__u64 res;

	/*
	 Received time is supposed to be derived from an NTP in a form of
	 (NTP.second * 1000 + NTP.fraction / 1000) & 0xFFFFFFFF
	 with many rollovers as NTP started in 1900. It's also assumed that "time"
	 is not older then 60 seconds
	*/
	if (ms > time + 60000 || ms + 60000 < time) ntp_ms += 0x100000000LL;

	res = ((((ntp_ms & 0xffffffff00000000LL) | time) << 16) / 1000) << 16;

	return res;
}


/*----------------------------------------------------------------------------*/
bool raopcl_is_connected(struct raopcl_s *p)
{
	bool rc;
	
	if (!p) return false;
	
	pthread_mutex_lock(&p->mutex);
	rc = rtspcl_is_connected(p->rtspcl);
	pthread_mutex_unlock(&p->mutex);	 

	return rc;
}


/*----------------------------------------------------------------------------*/
bool raopcl_is_sane(struct raopcl_s *p)
{
	if (p && p->state == RAOP_STREAMING &&
		(!rtspcl_is_sane(p->rtspcl) ||
		 (p->sane.audio.send + p->sane.audio.avail*5 +  p->sane.audio.select*50) >= 500 ||
		 p->sane.ctrl > 2 || p->sane.time > 2)) return false;

	return true;
}


/*----------------------------------------------------------------------------*/
bool raopcl_is_playing(struct raopcl_s *p)
{
	__u64 now_ts = NTP2TS(get_ntp(NULL), p->sample_rate);

	if (!p) return false;

	if (p->pause_ts || now_ts < p->head_ts + raopcl_latency(p)) return true;
	else return false;
}


/*----------------------------------------------------------------------------*/
static int rsa_encrypt(__u8 *text, int len, __u8 *res)
{
	RSA *rsa;
	__u8 modules[256];
	__u8 exponent[8];
	int size;
	char n[] =
			"59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC"
			"5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDR"
			"KSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuB"
			"OitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJ"
			"Q+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnh"
			"imNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==";
    char e[] = "AQAB";

	rsa = RSA_new();
	size = base64_decode(n, modules);
	rsa->n = BN_bin2bn(modules, size, NULL);
	size = base64_decode(e, exponent);
	rsa->e = BN_bin2bn(exponent, size, NULL);
	size = RSA_public_encrypt(len, text, res, rsa, RSA_PKCS1_OAEP_PADDING);
	RSA_free(rsa);

	return size;
}

/*----------------------------------------------------------------------------*/
static int raopcl_encrypt(raopcl_data_t *raopcld, __u8 *data, int size)
{
	__u8 *buf;
	int i=0,j;
	memcpy(raopcld->nv,raopcld->iv,16);
	while(i+16<=size){
		buf=data+i;
		for(j=0;j<16;j++) buf[j] ^= raopcld->nv[j];
		aes_encrypt(&raopcld->ctx, buf, buf);
		memcpy(raopcld->nv,buf,16);
		i+=16;
	}
#if 0
	if(i<size){
		__u8 tmp[16];
		LOG_INFO("[%p]: a block less than 16 bytes(%d) is not encrypted", raopcld, size-i);
		memset(tmp,0,16);
		memcpy(tmp,data+i,size-i);
		for(j=0;j<16;j++) tmp[j] ^= raopcld->nv[j];
		aes_encrypt(&raopcld->ctx, tmp, tmp);
		memcpy(raopcld->nv,tmp,16);
		memcpy(data+i,tmp,16);
		i+=16;
	}
#endif
	return i;
}


/*----------------------------------------------------------------------------*/
void raopcl_pause(struct raopcl_s *p)
{
	if (!p || p->state != RAOP_STREAMING) return;

	pthread_mutex_lock(&p->mutex);

	p->pause_ts = p->head_ts;
	p->flushing = true;

	pthread_mutex_unlock(&p->mutex);

	LOG_INFO("[%p]: set pause %Lu", p, p->pause_ts);
}


/*----------------------------------------------------------------------------*/
bool raopcl_start_at(struct raopcl_s *p, __u64 start_time)
{
	if (!p) return false;

	pthread_mutex_lock(&p->mutex);

	p->start_ts = NTP2TS(start_time, p->sample_rate);

	pthread_mutex_unlock(&p->mutex);

	LOG_INFO("[%p]: set start time %u.%u (ts:%Lu)", p, SEC(start_time), FRAC(start_time), p->start_ts);

	return true;
}


/*----------------------------------------------------------------------------*/
void raopcl_stop(struct raopcl_s *p)
{
	if (!p) return;

	pthread_mutex_lock(&p->mutex);

	p->flushing = true;
	p->pause_ts = 0;

	pthread_mutex_unlock(&p->mutex);
}


/*----------------------------------------------------------------------------*/
bool raopcl_accept_frames(struct raopcl_s *p)
{
	bool accept = false, first_pkt = false;
	__u64 now_ts;

	if (!p) return 0;

	pthread_mutex_lock(&p->mutex);

	// a flushing is pending
	if (p->flushing) {
		__u64 now = get_ntp(NULL);

		now_ts = NTP2TS(now, p->sample_rate);

		// Not flushed yet, but we have time to wait, so pretend we are full
		if (p->state != RAOP_FLUSHED && (!p->start_ts || p->start_ts > now_ts + p->latency_frames)) {
			pthread_mutex_unlock(&p->mutex);
			return false;
		 }

		// move to streaming only when really flushed - not when timedout
		if (p->state == RAOP_FLUSHED) {
			p->first_pkt = first_pkt = true;
			LOG_INFO("[%p]: begining to stream hts:%Lu n:%u.%u", p, p->head_ts, SECNTP(now));
			p->state = RAOP_STREAMING;
		}

		// either flushed or timedout, update pointers
		p->first_ts = p->start_ts ? p->start_ts : now_ts;

		// unpausing ...
		if (!p->pause_ts) {
			p->head_ts = p->first_ts;
			if (first_pkt) _raopcl_send_sync(p, true);
			LOG_INFO("[%p]: restarting w/o pause n:%u.%u, hts:%Lu", p, SECNTP(now), p->head_ts);
		}
		else {
			__u16 n, i, chunks = raopcl_latency(p) / p->chunk_len;

			// last head_ts shall be first + raopcl_latency - chunk_len
			p->head_ts = p->first_ts - p->chunk_len;

			if (first_pkt) _raopcl_send_sync(p, true);

			LOG_INFO("[%p]: restarting w/ pause n:%u.%u, hts:%Lu (re-send: %d)", p, SECNTP(now), p->head_ts, chunks);

			// search pause_ts in backlog, it should be backward, not too far
			for (n = p->seq_number, i = 0;
				 i < MAX_BACKLOG && p->backlog[n % MAX_BACKLOG].timestamp > p->pause_ts;
				 i++, n--);

			 // the resend shall go up to (including) pause_ts
			 n = (n - chunks + 1) % MAX_BACKLOG;

			// re-send old packets
			for (i = 0; i < chunks; i++) {
				rtp_audio_pkt_t *packet;
				__u16 reindex, index = (n + i) % MAX_BACKLOG;

				if (!p->backlog[index].buffer) continue;

				p->seq_number++;

				packet = (rtp_audio_pkt_t*) (p->backlog[index].buffer + sizeof(rtp_header_t));
				packet->hdr.seq[0] = (p->seq_number >> 8) & 0xff;
				packet->hdr.seq[1] = p->seq_number & 0xff;
				packet->timestamp = htonl(p->head_ts);
				packet->hdr.type = 0x60 | (p->first_pkt ? 0x80 : 0);
				p->first_pkt = false;

				// then replace packets in backlog in case
				reindex = p->seq_number % MAX_BACKLOG;

				p->backlog[reindex].seq_number = p->seq_number;
				p->backlog[reindex].timestamp = p->head_ts;
				if (p->backlog[reindex].buffer) free(p->backlog[reindex].buffer);
				p->backlog[reindex].buffer = p->backlog[index].buffer;
				p->backlog[reindex].size = p->backlog[index].size;
				p->backlog[index].buffer = NULL;

				p->head_ts += p->chunk_len;

				_raopcl_send_audio(p, packet, p->backlog[reindex].size);
			}

			LOG_DEBUG("[%p]: finished resend %u", p, i);
		}

		p->pause_ts = p->start_ts = 0;
		p->flushing = false;
	}

	// when paused, fix "now" at the time when it was paused.
	if (p->pause_ts) now_ts = p->pause_ts;
	else now_ts = NTP2TS(get_ntp(NULL), p->sample_rate);

	if (now_ts >= p->head_ts + p->chunk_len) accept = true;

	pthread_mutex_unlock(&p->mutex);

	return accept;
}


/*----------------------------------------------------------------------------*/
bool raopcl_send_chunk(struct raopcl_s *p, __u8 *sample, int frames, __u64 *playtime)
{
	u8_t *encoded, *buffer;
	rtp_audio_pkt_t *packet;
	size_t n;
	int size;
	__u64 now = get_ntp(NULL);

	if (!p || !sample) {
		LOG_ERROR("[%p]: something went wrong (s:%p)", p, sample);
		return false;
	}

	pthread_mutex_lock(&p->mutex);

	/*
	 Move to streaming state only when really flushed. In most cases, this is
	 done by the raopcl_accept_frames function, except when a player takes too
	 long to flush (JBL OnBeat) and we have to "fake" accepting frames
	*/
	if (p->state == RAOP_FLUSHED) {
		p->first_pkt = true;
		LOG_INFO("[%p]: begining to stream (LATE) hts:%Lu n:%u.%u", p, p->head_ts, SECNTP(now));
		p->state = RAOP_STREAMING;
		_raopcl_send_sync(p, true);
	}

	if (p->alac_codec) pcm_to_alac(p->alac_codec, sample, frames, &encoded, &size);
	else pcm_to_alac_fast(sample, frames, &encoded, &size, p->chunk_len);

	if ((buffer = malloc(sizeof(rtp_header_t) + sizeof(rtp_audio_pkt_t) + size)) == NULL) {
		pthread_mutex_unlock(&p->mutex);
		if (encoded) free(encoded);
		LOG_ERROR("[%p]: cannot allocate buffer",p);
		return false;
	}

	*playtime = TS2NTP(p->head_ts + raopcl_latency(p), p->sample_rate);

	LOG_SDEBUG("[%p]: sending audio ts:%Lu (pt:%u.%u now:%Lu) ", p, p->head_ts, SEC(*playtime), FRAC(*playtime), get_ntp(NULL));

	p->seq_number++;

	// packet is after re-transmit header
	packet = (rtp_audio_pkt_t *) (buffer + sizeof(rtp_header_t));
	packet->hdr.proto = 0x80;
	packet->hdr.type = 0x60 | (p->first_pkt ? 0x80 : 0);
	p->first_pkt = false;
	packet->hdr.seq[0] = (p->seq_number >> 8) & 0xff;
	packet->hdr.seq[1] = p->seq_number & 0xff;
	packet->timestamp = htonl(p->head_ts);
	packet->ssrc = htonl(p->ssrc);

	memcpy((u8_t*) packet + sizeof(rtp_audio_pkt_t), encoded, size);

	// with newer airport express, don't use encryption (??)
	if (p->encrypt) raopcl_encrypt(p, (u8_t*) packet + sizeof(rtp_audio_pkt_t), size);

	n = p->seq_number % MAX_BACKLOG;
	p->backlog[n].seq_number = p->seq_number;
	p->backlog[n].timestamp = p->head_ts;
	if (p->backlog[n].buffer) free(p->backlog[n].buffer);
	p->backlog[n].buffer = buffer;
	p->backlog[n].size = sizeof(rtp_audio_pkt_t) + size;

	p->head_ts += p->chunk_len;

	_raopcl_send_audio(p, packet, sizeof(rtp_audio_pkt_t) + size);

	pthread_mutex_unlock(&p->mutex);

	if (NTP2MS(*playtime) % 10000 < 8) {
		LOG_INFO("[%p]: check n:%u p:%u ts:%Lu sn:%u\n               "
				  "retr: %u, avail: %u, send: %u, select: %u)", p,
				 MSEC(now), MSEC(*playtime), p->head_ts, p->seq_number,
				 p->retransmit, p->sane.audio.avail, p->sane.audio.send,
				 p->sane.audio.select);
	}

	if (encoded) free(encoded);

	return true;
}


/*----------------------------------------------------------------------------*/
bool _raopcl_send_audio(struct raopcl_s *p, rtp_audio_pkt_t *packet, int size)
{
	struct timeval timeout;
	fd_set wfds;
	struct sockaddr_in addr;
	size_t n;
	bool ret = true;

	/*
	 Do not send if audio port closed or we are not yet in streaming state. We
	 might be just waiting for flush to happen in the case of a device taking a
	 lot of time to connect, so avoid disturbing it with frames. Still, for sync
	 reasons or when a starting time has been set, it's normal that the caller
	 uses raopcld_accept_frames() and tries to send frames even before the
	 connect has returned in case of multi-threaded application
	*/
	if (p->rtp_ports.audio.fd == -1 || p->state != RAOP_STREAMING) return false;

	addr.sin_family = AF_INET;
	addr.sin_addr = p->host_addr;
	addr.sin_port = htons(p->rtp_ports.audio.rport);

	FD_ZERO(&wfds);
	FD_SET(p->rtp_ports.audio.fd, &wfds);

	/*
	  The audio socket is non blocking, so we can can wait socket availability
	  but not too much. Half of the packet size if a good value. There is the
	  backlog buffer to re-send packets if needed, so nothign is lost
	*/
	timeout.tv_sec = 0;
	timeout.tv_usec = (p->chunk_len * 1000000L) / (p->sample_rate * 2);

	if (select(p->rtp_ports.audio.fd + 1, NULL, &wfds, NULL, &timeout) == -1) {
		LOG_ERROR("[%p]: audio socket closed", p);
		p->sane.audio.select++;
	}
	else p->sane.audio.select = 0;

	if (FD_ISSET(p->rtp_ports.audio.fd, &wfds)) {
		n = sendto(p->rtp_ports.audio.fd, (void*) packet, + size, 0, (void*) &addr, sizeof(addr));
		if (n != size) {
			LOG_DEBUG("[%p]: error sending audio packet", p);
			ret = false;
			p->sane.audio.send++;
		}
		else p->sane.audio.send = 0;
		p->sane.audio.avail = 0;
	}
	else {
		LOG_DEBUG("[%p]: audio socket unavailable", p);
		ret = false;
		p->sane.audio.avail++;
	}

	return ret;
}


/*----------------------------------------------------------------------------*/
struct raopcl_s *raopcl_create(struct in_addr local, char *DACP_id, char *active_remote,
							   raop_codec_t codec, bool alac_encode, int chunk_len,
							   int latency_frames, raop_crypto_t crypto, bool auth,
							   int sample_rate, int sample_size, int channels, float volume)
{
	raopcl_data_t *raopcld;

	if (chunk_len > MAX_SAMPLES_PER_CHUNK) {
		LOG_ERROR("Chunk length must below %d", MAX_SAMPLES_PER_CHUNK);
		return NULL;
	}

	// seed random generator
	raopcld = malloc(sizeof(raopcl_data_t));
	RAND_seed(raopcld, sizeof(raopcl_data_t));
	memset(raopcld, 0, sizeof(raopcl_data_t));

	//  raopcld->sane is set to 0
	raopcld->sample_rate = sample_rate;
	raopcld->sample_size = sample_size;
	raopcld->channels = channels;
	raopcld->volume = volume;
	raopcld->codec = codec;
	raopcld->crypto = crypto;
	raopcld->auth = auth;
	raopcld->latency_frames = max(latency_frames, RAOP_LATENCY_MIN);
	raopcld->chunk_len = chunk_len;
	strcpy(raopcld->DACP_id, DACP_id ? DACP_id : "");
	strcpy(raopcld->active_remote, active_remote ? active_remote : "");
	raopcld->local_addr = local;
	raopcld->rtp_ports.ctrl.fd = raopcld->rtp_ports.time.fd = raopcld->rtp_ports.audio.fd = -1;
	raopcld->seq_number = _random(0xffff);

	// init RTSP if needed
	if (((raopcld->rtspcl = rtspcl_create("iTunes/7.6.2 (Windows; N;)")) == NULL)) {
		LOG_ERROR("[%p]: Cannot create RTSP context", raopcld);
		free(raopcld);
		return NULL;
	}

	if (alac_encode && (raopcld->alac_codec = alac_create_codec(raopcld->chunk_len, sample_rate, sample_size, channels)) == NULL) {
		LOG_WARN("[%p]: cannot create ALAC codec", raopcld);
	}

	LOG_INFO("[%p]: using %s coding", raopcld, raopcld->alac_codec ? "ALAC" : "PCM");

	pthread_mutex_init(&raopcld->mutex, NULL);

	RAND_bytes(raopcld->iv, sizeof(raopcld->iv));
	VALGRIND_MAKE_MEM_DEFINED(raopcld->iv, sizeof(raopcld->iv));
	RAND_bytes(raopcld->key, sizeof(raopcld->key));
	VALGRIND_MAKE_MEM_DEFINED(raopcld->key, sizeof(raopcld->key));

	memcpy(raopcld->nv, raopcld->iv, sizeof(raopcld->nv));
	aes_set_key(&raopcld->ctx, raopcld->key, 128);

	raopcl_sanitize(raopcld);

	return raopcld;
}


/*----------------------------------------------------------------------------*/
static void _raopcl_terminate_rtp(struct raopcl_s *p)
{
	// Terminate RTP threads and close sockets
	p->ctrl_running = false;
	pthread_join(p->ctrl_thread, NULL);

	p->time_running = false;
	pthread_join(p->time_thread, NULL);

	if (p->rtp_ports.ctrl.fd != -1) close(p->rtp_ports.ctrl.fd);
	if (p->rtp_ports.time.fd != -1) close(p->rtp_ports.time.fd);
	if (p->rtp_ports.audio.fd != -1) close(p->rtp_ports.audio.fd);

	p->rtp_ports.ctrl.fd = p->rtp_ports.time.fd = p->rtp_ports.audio.fd = -1;
}


/*----------------------------------------------------------------------------*/
bool raopcl_set_volume(struct raopcl_s *p, float vol)
{
	char a[128];

	if (!p) return false;

	p->volume = vol;

	if (!p->rtspcl || p->state < RAOP_FLUSHED) return true;

	sprintf(a, "volume: %f\r\n", vol);

	return rtspcl_set_parameter(p->rtspcl, a);
}


/*----------------------------------------------------------------------------*/
// minimum=0, maximum=100
float raopcl_float_volume(int vol)
{
	if (vol == 0) return -144.0;
	return VOLUME_MIN + ((VOLUME_MAX - VOLUME_MIN) * (float) vol) / 100;
}



/*----------------------------------------------------------------------------*/
bool raopcl_set_progress_ms(struct raopcl_s *p, __u32 elapsed, __u32 duration)
{
	return raopcl_set_progress(p, MS2NTP(elapsed), MS2NTP(duration));
}


/*----------------------------------------------------------------------------*/
bool raopcl_set_progress(struct raopcl_s *p, __u64 elapsed, __u64 duration)
{
	char a[128];
	__u64 start, end, now;

	if (!p || !p->rtspcl || p->state < RAOP_STREAMING) return false;

	now = NTP2TS(get_ntp(NULL), p->sample_rate);
	start = now - NTP2TS(elapsed, p->sample_rate);
	end = duration ? start + NTP2TS(duration, p->sample_rate) : now;

	sprintf(a, "progress: %u/%u/%u\r\n", (__u32) start, (__u32) now, (__u32) end);

	return rtspcl_set_parameter(p->rtspcl, a);
}


/*----------------------------------------------------------------------------*/
bool raopcl_set_artwork(struct raopcl_s *p, char *content_type, int size, char *image)
{
	if (!p || !p->rtspcl || p->state < RAOP_FLUSHED) return false;

	return rtspcl_set_artwork(p->rtspcl, p->head_ts, content_type, size, image);
}


/*----------------------------------------------------------------------------*/
bool raopcl_set_daap(struct raopcl_s *p, int count, ...)
{
	va_list args;

	if (!p || p->state < RAOP_FLUSHED) return false;

	va_start(args, count);

	return rtspcl_set_daap(p->rtspcl, p->head_ts, count, args);
}


/*----------------------------------------------------------------------------*/
static bool raopcl_set_sdp(struct raopcl_s *p, char *sdp)
{
	bool rc = true;

   // codec
	switch (p->codec) {

		case RAOP_ALAC: {
			char buf[256];

			sprintf(buf,
					"m=audio 0 RTP/AVP 96\r\n"
					"a=rtpmap:96 AppleLossless\r\n"
					"a=fmtp:96 %d 0 %d 40 10 14 %d 255 0 0 %d\r\n",
					p->chunk_len, p->sample_size, p->channels, p->sample_rate);
			/* maybe one day I'll figure out how to send raw PCM ...
			sprintf(buf,
					"m=audio 0 RTP/AVP 96\r\n"
					"a=rtpmap:96 L16/44100/2\r\n",
			*/
			strcat(sdp, buf);
			break;
		}
		default:
			rc = false;
			LOG_ERROR("[%p]: unsupported codec: %d", p, p->codec);
			break;
	}

	// add encryption if required - only RSA
	switch (p->crypto ) {
		case RAOP_RSA: {
			char *key = NULL, *iv = NULL, *buf;
			__u8 rsakey[512];
			int i;

			i = rsa_encrypt(p->key, 16, rsakey);
			base64_encode(rsakey, i, &key);
			remove_char_from_string(key, '=');
			base64_encode(p->iv, 16, &iv);
			remove_char_from_string(iv, '=');
			buf = malloc(strlen(key) + strlen(iv) + 128);
			sprintf(buf, "a=rsaaeskey:%s\r\n"
						"a=aesiv:%s\r\n",
						key, iv);
			strcat(sdp, buf);
			free(key);
			free(iv);
			free(buf);
			break;
		}
		case RAOP_CLEAR:
			break;
		default:
			rc = false;
			LOG_ERROR("[%p]: unsupported encryption: %d", p, p->crypto);
	}

	return rc;
}


/*----------------------------------------------------------------------------*/
static bool raopcl_analyse_setup(struct raopcl_s *p, key_data_t *setup_kd)
{
	char *buf, *token, *pc;
	const char delimiters[] = ";";
	bool rc = true;

/*
	// get audio jack info
	if ((buf = kd_lookup(setup_kd,"Audio-Jack-Status")) == NULL) {
		LOG_ERROR("[%p]: Audio-Jack-Status is missing", p);
		rc = false;
	}

	token = strtok(buf,delimiters);
	while(token){
		if ((pc = strstr(token, "=")) != NULL){
			*pc = 0;
			if(!strcmp(token,"type") && !strcmp(pc + 1,"digital")) p->ajtype = JACK_TYPE_DIGITAL;
		}
		else {
			if (!strcmp(token,"connected")) p->ajstatus = JACK_STATUS_CONNECTED;
		}
		token = strtok(NULL, delimiters);
	}
*/

	// get transport (port ...) info
	if ((buf = kd_lookup(setup_kd, "Transport")) == NULL){
		LOG_ERROR("[%p]: no transport in response", p);
		rc = false;
	}

	token = strtok(buf, delimiters);
	while (token) {
		if ((pc = strstr(token, "=")) != NULL) {
			*pc = 0;
			if (!strcmp(token,"server_port")) p->rtp_ports.audio.rport=atoi(pc+1);
			if (!strcmp(token,"control_port")) p->rtp_ports.ctrl.rport=atoi(pc+1);
			if (!strcmp(token,"timing_port")) p->rtp_ports.time.rport=atoi(pc+1);
		}
		token = strtok(NULL,delimiters);
	}

	if (!p->rtp_ports.audio.rport || !p->rtp_ports.ctrl.rport || !p->rtp_ports.time.rport) {
		LOG_ERROR("[%p]: missing a RTP port in response", p);
		rc = false;
	}

	return rc;
}


/*----------------------------------------------------------------------------*/
bool raopcl_connect(struct raopcl_s *p, struct in_addr host, __u16 destport, raop_codec_t codec)
{
	struct {
		__u32 sid;
		__u64 sci;
		__u8 sac[16];
	} seed;
	char sid[10+1], sci[16+1];
	char *sac = NULL;
	char sdp[1024];
	key_data_t kd[MAX_KD];
	char *buf;

	if (!p) return false;

	if (p->state >= RAOP_FLUSHING) return true;

	kd[0].key = NULL;

	if (host.s_addr != INADDR_ANY) p->host_addr.s_addr = host.s_addr;
	if (codec != RAOP_NOCODEC) p->codec = codec;
	if (destport != 0) p->rtsp_port = destport;

	RAND_bytes((__u8*) &p->ssrc, sizeof(p->ssrc));
	VALGRIND_MAKE_MEM_DEFINED(&p->ssrc, sizeof(p->ssrc));

	p->encrypt = (p->crypto != RAOP_CLEAR);
	memset(&p->sane, 0, sizeof(p->sane));
	p->retransmit = 0;

	RAND_bytes((__u8*) &seed, sizeof(seed));
	VALGRIND_MAKE_MEM_DEFINED(&seed, sizeof(seed));
	sprintf(sid, "%010lu", (long unsigned int) seed.sid);
	sprintf(sci, "%016llx", (long long int) seed.sci);

	// RTSP misc setup
	rtspcl_add_exthds(p->rtspcl,"Client-Instance", sci);
	if (*p->active_remote) rtspcl_add_exthds(p->rtspcl,"Active-Remote", p->active_remote);
	if (*p->DACP_id) rtspcl_add_exthds(p->rtspcl,"DACP-ID", p->DACP_id);

	// RTSP connect
	if (!rtspcl_connect(p->rtspcl, p->local_addr, host, destport, sid)) goto erexit;

	LOG_INFO("[%p]: local interface %s", p, rtspcl_local_ip(p->rtspcl));

	// RTSP auth
	// if(rtspcl_auth_setup(p->rtspcl)) goto erexit;

	// RTSP get options (not needed)
	// if (p->state == RAOP_DOWN_FULL && !rtspcl_options(p->rtspcl)) goto erexit;

	// build sdp parameter
	buf = strdup(inet_ntoa(host));
	sprintf(sdp,
			"v=0\r\n"
			"o=iTunes %s 0 IN IP4 %s\r\n"
			"s=iTunes\r\n"
			"c=IN IP4 %s\r\n"
			"t=0 0\r\n",
			sid, rtspcl_local_ip(p->rtspcl), buf);
	free(buf);

	if (!raopcl_set_sdp(p, sdp)) goto erexit;

	// AppleTV expects now the timing port ot be opened BEFORE the setup message
	p->rtp_ports.time.lport = p->rtp_ports.time.rport = 0;
	if ((p->rtp_ports.time.fd = open_udp_socket(p->local_addr, &p->rtp_ports.time.lport, true)) == -1) goto erexit;
	p->time_running = true;
	pthread_create(&p->time_thread, NULL, _rtp_timing_thread, (void*) p);

	// RTSP ANNOUNCE
	if (p->auth && p->crypto) {
		base64_encode(&seed.sac, 16, &sac);
		remove_char_from_string(sac, '=');
		if (!rtspcl_add_exthds(p->rtspcl, "Apple-Challenge", sac)) goto erexit;
		if (!rtspcl_announce_sdp(p->rtspcl, sdp))goto erexit;
		if (!rtspcl_mark_del_exthds(p->rtspcl, "Apple-Challenge")) goto erexit;
	}
	else if (!rtspcl_announce_sdp(p->rtspcl, sdp))goto erexit;

	// open RTP sockets, need local ports here before sending SETUP
	p->rtp_ports.ctrl.lport = p->rtp_ports.audio.lport = 0;
	if ((p->rtp_ports.ctrl.fd = open_udp_socket(p->local_addr, &p->rtp_ports.ctrl.lport, true)) == -1) goto erexit;
	if ((p->rtp_ports.audio.fd = open_udp_socket(p->local_addr, &p->rtp_ports.audio.lport, false)) == -1) goto erexit;

	// RTSP SETUP : get all RTP destination ports
	if (!rtspcl_setup(p->rtspcl, &p->rtp_ports, kd)) goto erexit;
	if (!raopcl_analyse_setup(p, kd)) goto erexit;
	free_kd(kd);

	LOG_DEBUG( "[%p]:opened audio socket   l:%5d r:%d", p, p->rtp_ports.audio.lport, p->rtp_ports.audio.rport );
	LOG_DEBUG( "[%p]:opened timing socket  l:%5d r:%d", p, p->rtp_ports.time.lport, p->rtp_ports.time.rport );
	LOG_DEBUG( "[%p]:opened control socket l:%5d r:%d", p, p->rtp_ports.ctrl.lport, p->rtp_ports.ctrl.rport );

	if (!rtspcl_record(p->rtspcl, p->seq_number + 1, NTP2TS(get_ntp(NULL), p->sample_rate), kd)) goto erexit;

	if (kd_lookup(kd, "Audio-Latency")) {
		int latency = atoi(kd_lookup(kd, "Audio-Latency"));

		p->latency_frames = max((__u32) latency, p->latency_frames);
	}
	free_kd(kd);

	p->ctrl_running = true;
	pthread_create(&p->ctrl_thread, NULL, _rtp_control_thread, (void*) p);

	pthread_mutex_lock(&p->mutex);
	// as connect might take time, state might already have been set
	if (p->state == RAOP_DOWN) p->state = RAOP_FLUSHED;
	pthread_mutex_unlock(&p->mutex);

	if (((p->volume >= -30 && p->volume <= 0) || p->volume == -144.0) && !raopcl_set_volume(p, p->volume)) goto erexit;

	if (sac) free(sac);
	return true;

 erexit:
	if (sac) free(sac);
	free_kd(kd);
	_raopcl_disconnect(p, true);

	return false;
}


/*----------------------------------------------------------------------------*/
bool raopcl_flush(struct raopcl_s *p)
{
	bool rc;
	__u16 seq_number;
	__u32 timestamp;

	if (!p || p->state != RAOP_STREAMING) return false;

	pthread_mutex_lock(&p->mutex);
	p->state = RAOP_FLUSHING;
	p->retransmit = 0;
	seq_number = p->seq_number;
	timestamp = p->head_ts;
	pthread_mutex_unlock(&p->mutex);

	LOG_INFO("[%p]: flushing up to s:%u ts:%Lu", p, seq_number, p->head_ts);

	// everything BELOW these values should be FLUSHED ==> the +1 is mandatory
	rc = rtspcl_flush(p->rtspcl, seq_number + 1, timestamp + 1);

	pthread_mutex_lock(&p->mutex);
	p->state = RAOP_FLUSHED;
	pthread_mutex_unlock(&p->mutex);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool _raopcl_disconnect(struct raopcl_s *p, bool force)
{
	bool rc = true;

	if (!force && (!p || p->state == RAOP_DOWN)) return true;

	pthread_mutex_lock(&p->mutex);
	p->state = RAOP_DOWN;
	pthread_mutex_unlock(&p->mutex);

	_raopcl_terminate_rtp(p);
	
	rc = rtspcl_flush(p->rtspcl, p->seq_number + 1, p->head_ts + 1);
	rc &= rtspcl_disconnect(p->rtspcl);
	rc &= rtspcl_remove_all_exthds(p->rtspcl);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool raopcl_disconnect(struct raopcl_s *p) 
{
	return _raopcl_disconnect(p, false);
}


/*----------------------------------------------------------------------------*/
bool raopcl_repair(struct raopcl_s *p)
{
	bool rc = true;

	if (!p) return false;

	pthread_mutex_lock(&p->mutex);
	p->state = RAOP_DOWN;
	pthread_mutex_unlock(&p->mutex);

	_raopcl_terminate_rtp(p);

	// not thread safe, but does not matter really, all we want is "some" flush
	rc &= rtspcl_flush(p->rtspcl, p->seq_number + 1, p->head_ts + 1);
	rc &= rtspcl_disconnect(p->rtspcl);
	rc &= rtspcl_remove_all_exthds(p->rtspcl);

	// this will put us again in FLUSHED state
	rc &= raopcl_connect(p, p->host_addr, p->rtsp_port, p->codec);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool raopcl_destroy(struct raopcl_s *p)
{
	int i;
	bool rc;

	if (!p) return false;

	rc = raopcl_disconnect(p);
	rc &= rtspcl_destroy(p->rtspcl);
	pthread_mutex_destroy(&p->mutex);

	for (i = 0; i < MAX_BACKLOG; i++) {
		if (p->backlog[i].buffer) {
			free(p->backlog[i].buffer);
		}
	}

	if (p->alac_codec) alac_destroy_codec(p->alac_codec);

	free(p);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool raopcl_sanitize(struct raopcl_s *p)
{
	if (!p) return false;

	pthread_mutex_trylock(&p->mutex);

	p->state = RAOP_DOWN;
	p->head_ts = p->pause_ts = p->start_ts = p->first_ts = 0;
	p->first_pkt = false;
	p->flushing = true;

	pthread_mutex_unlock(&p->mutex);

	return true;
}


/*----------------------------------------------------------------------------*/
void _raopcl_send_sync(struct raopcl_s *raopcld, bool first)
{
	struct sockaddr_in addr;
	rtp_sync_pkt_t rsp;
	__u64 now, timestamp;
	int n;

	addr.sin_family = AF_INET;
	addr.sin_addr = raopcld->host_addr;
	addr.sin_port = htons(raopcld->rtp_ports.ctrl.rport);

	// do not send timesync on FLUSHED
	if (raopcld->state != RAOP_STREAMING) return;

	rsp.hdr.proto = 0x80 | (first ? 0x10 : 0x00);
	rsp.hdr.type = 0x54 | 0x80;
	// seems that seq=7 shall be forced
	rsp.hdr.seq[0] = 0;
	rsp.hdr.seq[1] = 7;

	// first sync is called with mutex locked, so don't block
	if (!first) pthread_mutex_lock(&raopcld->mutex);

	timestamp = raopcld->head_ts;
	now = TS2NTP(timestamp, raopcld->sample_rate);

	// set the NTP time in network order
	rsp.curr_time.seconds = htonl(now >> 32);
	rsp.curr_time.fraction = htonl(now);

	// The DAC time is synchronized with gettime_ms(), minus the latency.
	rsp.rtp_timestamp = htonl(timestamp);
	rsp.rtp_timestamp_latency = htonl(timestamp - raopcld->latency_frames);

	n = sendto(raopcld->rtp_ports.ctrl.fd, (void*) &rsp, sizeof(rsp), 0, (void*) &addr, sizeof(addr));

	if (!first) pthread_mutex_unlock(&raopcld->mutex);

	LOG_DEBUG("[%p]: sync ntp:%u.%u (ts:%Lu)", raopcld, SEC(now), FRAC(now), raopcld->head_ts);

	if (n < 0) LOG_ERROR("[%p]: write error: %s", raopcld, strerror(errno));
	if (n == 0) LOG_INFO("[%p]: write, disconnected on the other end", raopcld);
}


/*----------------------------------------------------------------------------*/
void *_rtp_timing_thread(void *args)
{
	raopcl_data_t *raopcld = (raopcl_data_t*) args;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr = raopcld->host_addr;
	addr.sin_port = htons(raopcld->rtp_ports.time.rport);

	while (raopcld->time_running)
	{
		rtp_time_pkt_t req;
		struct timeval timeout = { 1, 0 };
		fd_set rfds;
		int n;

		FD_ZERO(&rfds);
		FD_SET(raopcld->rtp_ports.time.fd, &rfds);

		if ((n = select(raopcld->rtp_ports.time.fd + 1, &rfds, NULL, NULL, &timeout)) == -1) {
			LOG_ERROR("[%p]: raopcl_time_connect: socket closed on the other end", raopcld);
			usleep(100000);
			continue;
		}

		if (!FD_ISSET(raopcld->rtp_ports.time.fd, &rfds)) continue;

		if (addr.sin_port) {
			n = recv(raopcld->rtp_ports.time.fd, (void*) &req, sizeof(req), 0);
		}
		else {
			struct sockaddr_in client;
			int len = sizeof(client);
			n = recvfrom(raopcld->rtp_ports.time.fd, (void*) &req, sizeof(req), 0, (struct sockaddr *)&client, (socklen_t *)&len);
			addr.sin_port = client.sin_port;
			LOG_DEBUG("[%p]: NTP remote port: %d", raopcld, ntohs(addr.sin_port));
		}

		if( n > 0) 	{
			rtp_time_pkt_t rsp;

			rsp.hdr = req.hdr;
			rsp.hdr.type = 0x53 | 0x80;
			// just copy the request header or set seq=7 and timestamp=0
			rsp.ref_time = req.send_time;
			VALGRIND_MAKE_MEM_DEFINED(&rsp, sizeof(rsp));

			// transform timeval into NTP and set network order
			get_ntp(&rsp.recv_time);

			rsp.recv_time.seconds = htonl(rsp.recv_time.seconds);
			rsp.recv_time.fraction = htonl(rsp.recv_time.fraction);
			rsp.send_time = rsp.recv_time; // might need to add a few fraction ?

			n = sendto(raopcld->rtp_ports.time.fd, (void*) &rsp, sizeof(rsp), 0, (void*) &addr, sizeof(addr));

			if (n != (int) sizeof(rsp)) {
			   LOG_ERROR("[%p]: error responding to sync", raopcld);
			}

			LOG_DEBUG( "[%p]: NTP sync: %u.%u (ref %u.%u)", raopcld, ntohl(rsp.send_time.seconds), ntohl(rsp.send_time.fraction),
															ntohl(rsp.ref_time.seconds), ntohl(rsp.ref_time.fraction) );

		}

		if (n < 0) {
		   LOG_ERROR("[%p]: read error: %s", raopcld, strerror(errno));
		}

		if (n == 0) {
			LOG_ERROR("[%p]: read, disconnected on the other end", raopcld);
			usleep(100000);
			continue;
		}
	}

	return NULL;
}


/*----------------------------------------------------------------------------*/
void *_rtp_control_thread(void *args)
{
	raopcl_data_t *raopcld = (raopcl_data_t*) args;

	while (raopcld->ctrl_running)	{
		struct timeval timeout = { 1, 0 };
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(raopcld->rtp_ports.ctrl.fd, &rfds);

		if (select(raopcld->rtp_ports.ctrl.fd + 1, &rfds, NULL, NULL, &timeout) == -1) {
			if (raopcld->ctrl_running) {
				LOG_ERROR("[%p]: control socket closed", raopcld);
				raopcld->sane.ctrl++;
				sleep(1);
			}
			continue;
		}
		
		if (FD_ISSET(raopcld->rtp_ports.ctrl.fd, &rfds)) {
			rtp_lost_pkt_t lost;
			int i, n, missed;

			n = recv(raopcld->rtp_ports.ctrl.fd, (void*) &lost, sizeof(lost), 0);

			if (n < 0) continue;

			lost.seq_number = ntohs(lost.seq_number);
			lost.n = ntohs(lost.n);

			if (n != sizeof(lost)) {
				LOG_ERROR("[%p]: error in received request sn:%d n:%d (recv:%d)",
						  raopcld, lost.seq_number, lost.n, n);
				lost.n = 0;
				lost.seq_number = 0;
				raopcld->sane.ctrl++;
			}
			else raopcld->sane.ctrl = 0;

			pthread_mutex_lock(&raopcld->mutex);

			for (missed = 0, i = 0; i < lost.n; i++) {
				u16_t index = (lost.seq_number + i) % MAX_BACKLOG;

				if (raopcld->backlog[index].seq_number == lost.seq_number + i) {
					struct sockaddr_in addr;
					rtp_header_t *hdr = (rtp_header_t*) raopcld->backlog[index].buffer;

					// packet have been released meanwhile, be extra cautious
					if (!hdr) continue;

					hdr->proto = 0x80;
					hdr->type = 0x56 | 0x80;
					hdr->seq[0] = 0;
					hdr->seq[1] = 1;

					addr.sin_family = AF_INET;
					addr.sin_addr = raopcld->host_addr;
					addr.sin_port = htons(raopcld->rtp_ports.ctrl.rport);

					raopcld->retransmit++;

					n = sendto(raopcld->rtp_ports.ctrl.fd, (void*) hdr,
							   sizeof(rtp_header_t) + raopcld->backlog[index].size,
							   0, (void*) &addr, sizeof(addr));

					if (n == -1) {
						LOG_WARN("[%p]: error resending lost packet sn:%u (n:%d)",
								   raopcld, lost.seq_number + i, n);
					}
				}
				else {
					LOG_WARN("[%p]: lost packet out of backlog %u", raopcld, lost.seq_number + i);
				}
			}

			pthread_mutex_unlock(&raopcld->mutex);

			LOG_DEBUG("[%p]: retransmit packet sn:%d nb:%d (mis:%d)",
					  raopcld, lost.seq_number, lost.n, missed);

			continue;
		}

		_raopcl_send_sync(raopcld, false);
	}

	return NULL;
}





