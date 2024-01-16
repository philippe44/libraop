/*
 * RAOP : simulate an airplay device, streamer and slave-clocked replay engine
 * 
 * Copyright (c) James Laird 2011
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>
#include <openssl/aes.h>

#include "platform.h"
#include "raop_server.h"
#include "raop_streamer.h"
#include "encoder.h"
#include "alac.h"

#include "cross_net.h"
#include "cross_log.h"
#include "cross_util.h"

#define NTP2MS(ntp) ((((ntp) >> 10) * 1000L) >> 22)
#define MS2NTP(ms) (((((uint64_t) (ms)) << 22) / 1000) << 10)
#define NTP2TS(ntp, rate) ((((ntp) >> 16) * (rate)) >> 16)
#define TS2NTP(ts, rate)  (((((uint64_t) (ts)) << 16) / (rate)) << 16)
#define MS2TS(ms, rate) ((((uint64_t) (ms)) * (rate)) / 1000)
#define TS2MS(ts, rate) NTP2MS(TS2NTP(ts,rate))

#define GAP_THRES	8
#define GAP_COUNT	20

extern log_level 	raop_loglevel;
static log_level 	*loglevel = &raop_loglevel;

// #define __RTP_STORE

// default buffer size
#define BUFFER_FRAMES 2048
#define MAX_PACKET    2048
#define CACHE_SIZE (2048*1024)

#define RTP_SYNC 0x01
#define NTP_SYNC 0x02

#define RESEND_TO	150

#define ICY_LEN_MAX	 (255*16+1)

enum { DATA, CONTROL, TIMING };

typedef uint16_t seq_t;
typedef struct audio_buffer_entry {   // decoded audio packets
	int ready;
	uint32_t rtptime, last_resend;
	int16_t *data;
	int len;
} abuf_t;
 
typedef struct raopst_s {
#ifdef __RTP_STORE
	FILE *rtpIN, *rtpOUT, *httpOUT;
#endif
	bool running;
	unsigned char aesiv[16];
	AES_KEY aes;
	bool decrypt, range;
	int frame_size;
	int in_frames, out_frames;
	struct in_addr host, peer;
	struct sockaddr_in rtp_host;
	struct encoder_s* encoder;
	struct {
		unsigned short rport, lport;
		int sock;
	} rtp_sockets[3]; 					 // data, control, timing
	struct timing_s {
		bool drift;
		uint64_t local, remote, rtp_remote;
		uint32_t count, gap_count;
		int64_t gap_sum, gap_adjust;
	} timing;
	struct {
		uint32_t 	rtp, time;
		uint8_t  	status;
		bool	first, required;
	} synchro;
	struct {
		uint32_t time;
		seq_t seqno;
		uint32_t rtptime;
	} record;
	int latency;			// rtp hold depth in samples
	int delay;              // http startup silence fill frames
	uint32_t resent_frames;	// total recovered frames
	uint32_t silent_frames;	// total silence frames
	uint32_t silence_count;	// counter for startup silence frames
	uint32_t filled_frames;    // silence frames in current silence episode
	bool http_fill;         // fill when missing or just wait
	bool pause;				// set when pause and silent frames must be produced
	int skip;				// number of frames to skip to keep sync alignement
	abuf_t audio_buffer[BUFFER_FRAMES];
	int http_listener;
	seq_t ab_read, ab_write;
	pthread_mutex_t ab_mutex;
	pthread_t http_thread, rtp_thread;
	struct {
		bool enabled, active;
		size_t interval, remain;
		bool  updated;
	} icy;
	raopsr_metadata_t metadata;
	char *silence_frame;
	alac_file *alac_codec;
	int flush_seqno;
	bool playing, silence, http_ready;
	raopst_cb_t event_cb;
	raop_http_cb_t http_cb;
	void *owner;
	uint8_t *http_cache;
	size_t http_count;
	int http_length;
	bool close_socket;
} raopst_t;

#define BUFIDX(seqno) ((seq_t)(seqno) % BUFFER_FRAMES)
static void 	buffer_alloc(abuf_t *audio_buffer, int size);
static void 	buffer_release(abuf_t *audio_buffer);
static void 	buffer_reset(abuf_t *audio_buffer);

static bool 	rtp_request_resend(raopst_t *ctx, seq_t first, seq_t last);
static bool 	rtp_request_timing(raopst_t *ctx);
static void*	rtp_thread_func(void *arg);

static void*	http_thread_func(void *arg);
static bool 	handle_http(raopst_t *ctx, int sock);

static int	  	seq_order(seq_t a, seq_t b);

/*---------------------------------------------------------------------------*/
static alac_file* alac_init(int fmtp[32]) {
	int sample_size = fmtp[3];

	if (sample_size != 16) {
		LOG_ERROR("sample size must be 16 %d", sample_size);
		return false;
	}

	alac_file* alac = create_alac(sample_size, 2);

	if (!alac) {
		LOG_ERROR("cannot create alac codec", NULL);
		return NULL;
	}

	alac->setinfo_max_samples_per_frame = fmtp[1];
	alac->setinfo_7a 				= fmtp[2];
	alac->setinfo_sample_size 		= sample_size;
	alac->setinfo_rice_historymult = fmtp[4];
	alac->setinfo_rice_initialhistory = fmtp[5];
	alac->setinfo_rice_kmodifier 	= fmtp[6];
	alac->setinfo_7f 				= fmtp[7];
	alac->setinfo_80 				= fmtp[8];
	alac->setinfo_82 			    = fmtp[9];
	alac->setinfo_86 				= fmtp[10];
	alac->setinfo_8a_rate			= fmtp[11];
	allocate_buffers(alac);

	return alac;
}

/*---------------------------------------------------------------------------*/
raopst_resp_t raopst_init(struct in_addr host, struct in_addr peer, char *codec, bool metadata,
								bool sync, bool drift, bool range, char *latencies,
								char *aeskey, char *aesiv, char *fmtpstr,
								short unsigned pCtrlPort, short unsigned pTimingPort,
								void *owner,
								raopst_cb_t event_cb, raop_http_cb_t http_cb,
								unsigned short port_base, unsigned short port_range,
								int http_length) {
	char *arg, *p;
	int fmtp[12];
	bool rc = true;
	raopst_t *ctx = calloc(1, sizeof(raopst_t));
	raopst_resp_t resp = { 0, 0, 0, 0, NULL };
	struct {
		unsigned short count, offset;
	} port = { 0 };
	if (!port_base) port_range = 1;
	port.offset = rand() % port_range;

	if (!ctx) return resp;
	
	ctx->http_cache = malloc(CACHE_SIZE);
	ctx->http_length = http_length;
	ctx->host = host;
	ctx->peer = peer;
	ctx->rtp_host.sin_family = AF_INET;
	ctx->rtp_host.sin_addr.s_addr = INADDR_ANY;
	pthread_mutex_init(&ctx->ab_mutex, 0);
	ctx->flush_seqno = -1;

	// create the encoder
	ctx->encoder = encoder_create(codec, 44100, 2, 2, 0, &ctx->icy.interval);

	ctx->icy.enabled = metadata;
	ctx->latency = atoi(latencies);
	ctx->latency = (ctx->latency * 44100) / 1000;
	if (strstr(latencies, ":f")) ctx->http_fill = true;
	ctx->event_cb = event_cb;
	ctx->http_cb = http_cb;
	ctx->owner = owner;
	ctx->synchro.required = sync;
	ctx->timing.drift = drift;
	ctx->range = range;

	// write pointer = last written, read pointer = next to read so fill = w-r+1
	ctx->ab_read = ctx->ab_write + 1;

#ifdef __RTP_STORE
	ctx->rtpIN = fopen("airplay.rtpin", "wb");
	ctx->rtpOUT = fopen("airplay.rtpout", "wb");
	ctx->httpOUT = fopen("airplay.httpout", "wb");
#endif

	ctx->rtp_sockets[CONTROL].rport = pCtrlPort;
	ctx->rtp_sockets[TIMING].rport = pTimingPort;

	if (aesiv && aeskey) {
		memcpy(ctx->aesiv, aesiv, 16);
		AES_set_decrypt_key((unsigned char*) aeskey, 128, &ctx->aes);
		ctx->decrypt = true;
	}

	memset(fmtp, 0, sizeof(fmtp));
	for (int i = 0; (arg = strsep(&fmtpstr, " \t")); i++) fmtp[i] = atoi(arg);

	ctx->frame_size = fmtp[1];
	ctx->silence_frame = (char*) calloc(ctx->frame_size, 4);
	if ((p = strchr(latencies, ':')) != NULL) {
		ctx->delay = atoi(p + 1);
		ctx->delay = (ctx->delay * 44100) / (ctx->frame_size * 1000);
	}

	// alac decoder
	ctx->alac_codec = alac_init(fmtp);
	rc &= ctx->alac_codec != NULL;

	buffer_alloc(ctx->audio_buffer, ctx->frame_size*4);

	for (int i = 0; rc && i < 3; i++) {
		do {
			ctx->rtp_sockets[i].lport = port_base + ((port.offset + port.count++) % port_range);
			ctx->rtp_sockets[i].sock = bind_socket(ctx->host, &ctx->rtp_sockets[i].lport, SOCK_DGRAM);
		} while (ctx->rtp_sockets[i].sock < 0 && port.count < port_range);

		rc &= ctx->rtp_sockets[i].sock > 0;

		LOG_INFO("[%p]: UDP port-%d %hu", ctx, i, ctx->rtp_sockets[i].lport);
	}

	// create http port and start listening
	do {
		resp.hport = port_base + ((port.offset + port.count++) % port_range);
		ctx->http_listener = bind_socket(ctx->host, &resp.hport, SOCK_STREAM);
	} while (ctx->http_listener < 0 && port.count < port_range);

	int i = 128*1024;
	setsockopt(ctx->http_listener, SOL_SOCKET, SO_SNDBUF, (void*) &i, sizeof(i));
	rc &= ctx->http_listener > 0;
	rc &= listen(ctx->http_listener, 1) == 0;

	resp.cport = ctx->rtp_sockets[CONTROL].lport;
	resp.tport = ctx->rtp_sockets[TIMING].lport;
	resp.aport = ctx->rtp_sockets[DATA].lport;

	LOG_INFO("[%p]: HTTP listening port %hu", ctx, resp.hport);

	if (rc) {
		ctx->running = true;
		pthread_create(&ctx->rtp_thread, NULL, rtp_thread_func, (void *) ctx);
		pthread_create(&ctx->http_thread, NULL, http_thread_func, (void *) ctx);
	} else {
		raopst_end(ctx);
		ctx = NULL;
	}

	resp.ctx = ctx;

	return resp;
}

/*---------------------------------------------------------------------------*/
void raopst_metadata(struct raopst_s *ctx, raopsr_metadata_t *metadata) {
	pthread_mutex_lock(&ctx->ab_mutex);
	// free previous metadata if we have not been able to send them yet
	raopsr_metadata_free(&ctx->metadata);
	raopsr_metadata_copy(&ctx->metadata, metadata);
	ctx->icy.updated = true;
	pthread_mutex_unlock(&ctx->ab_mutex);
}

/*---------------------------------------------------------------------------*/
void raopst_end(raopst_t *ctx) {
	if (!ctx) return;

	if (ctx->running) {
		ctx->running = false;
		pthread_join(ctx->rtp_thread, NULL);
		pthread_join(ctx->http_thread, NULL);
	}

	shutdown_socket(ctx->http_listener);
	for (int i = 0; i < 3; i++) if (ctx->rtp_sockets[i].sock > 0) closesocket(ctx->rtp_sockets[i].sock);

	delete_alac(ctx->alac_codec);
	encoder_delete(ctx->encoder);

	pthread_mutex_destroy(&ctx->ab_mutex);
	buffer_release(ctx->audio_buffer);
	free(ctx->silence_frame);
	free(ctx->http_cache);
	raopsr_metadata_free(&ctx->metadata);
	free(ctx);

#ifdef __RTP_STORE
	fclose(ctx->rtpIN);
	fclose(ctx->rtpOUT);
	fclose(ctx->httpOUT);
#endif
}

/*---------------------------------------------------------------------------*/
bool raopst_flush(raopst_t *ctx, unsigned short seqno, unsigned int rtptime, bool exit_locked, bool silence) {
	bool stopped = true;
	uint32_t now = gettime_ms();

	pthread_mutex_lock(&ctx->ab_mutex);

	// always store flush seqno as we only want stricly above it, even when equal to RECORD
	ctx->flush_seqno = seqno;

	// we just need to have memorized the flush seqno
	if (now < ctx->record.time + 250 || (ctx->record.seqno == seqno && ctx->record.rtptime == rtptime)) {
		LOG_WARN("[%p]: FLUSH ignored (early or same as RECORD) %hu - %u", ctx, seqno, rtptime);
		stopped = false;
	} else {
		LOG_INFO("[%p]: FLUSH up to %hu - %u", ctx, seqno, rtptime);
		buffer_reset(ctx->audio_buffer);

		if (!silence) {
			ctx->playing = false;
			ctx->synchro.first = false;
			ctx->http_ready = false;
			ctx->close_socket = true;
			ctx->http_count = 0;
			ctx->ab_read = ctx->ab_write + 1;
			encoder_close(ctx->encoder);
		} else {
			ctx->pause = true;
		}
	}

	if (!exit_locked) pthread_mutex_unlock(&ctx->ab_mutex);
	return stopped;
}

/*---------------------------------------------------------------------------*/
void raopst_flush_release(raopst_t *ctx) {
	pthread_mutex_unlock(&ctx->ab_mutex);
}

/*---------------------------------------------------------------------------*/
void raopst_record(raopst_t *ctx, unsigned short seqno, unsigned rtptime) {
	ctx->record.seqno = seqno;
	ctx->record.rtptime = rtptime;
	ctx->record.time = gettime_ms();

	LOG_INFO("[%p]: record %hu %u", ctx, seqno, rtptime);
}

/*---------------------------------------------------------------------------*/
static void buffer_alloc(abuf_t *audio_buffer, int size) {
	for (int i = 0; i < BUFFER_FRAMES; i++) {
		audio_buffer[i].data = malloc(size);
		audio_buffer[i].ready = 0;
	}
}

/*---------------------------------------------------------------------------*/
static void buffer_release(abuf_t *audio_buffer) {
	for (int i = 0; i < BUFFER_FRAMES; i++) free(audio_buffer[i].data);
}

/*---------------------------------------------------------------------------*/
static void buffer_reset(abuf_t *audio_buffer) {
	for (int i = 0; i < BUFFER_FRAMES; i++) audio_buffer[i].ready = 0;
}

/*---------------------------------------------------------------------------*/
// the sequence numbers will wrap pretty often.
// this returns true if the second arg is after the first
static int seq_order(seq_t a, seq_t b) {
	int16_t d = b - a;
	return d > 0;
}

/*---------------------------------------------------------------------------*/
static void alac_decode(raopst_t *ctx, int16_t *dest, char *buf, int len, int *outsize) {
	unsigned char packet[MAX_PACKET];
	unsigned char iv[16];
	int aeslen;
	assert(len<=MAX_PACKET);

	if (ctx->decrypt) {
		aeslen = len & ~0xf;
		memcpy(iv, ctx->aesiv, sizeof(iv));
		AES_cbc_encrypt((unsigned char*)buf, packet, aeslen, &ctx->aes, iv, AES_DECRYPT);
		memcpy(packet+aeslen, buf+aeslen, len-aeslen);
		decode_frame(ctx->alac_codec, packet, dest, outsize);
	} else decode_frame(ctx->alac_codec, (unsigned char*) buf, dest, outsize);
}

/*---------------------------------------------------------------------------*/
static void buffer_put_packet(raopst_t *ctx, seq_t seqno, unsigned rtptime, bool first, char *data, int len) {
	abuf_t *abuf = NULL;

	pthread_mutex_lock(&ctx->ab_mutex);

	if (!ctx->playing) {
		if ((ctx->flush_seqno == -1 || seq_order(ctx->flush_seqno, seqno)) &&
		    (!ctx->synchro.required || ctx->synchro.first)) {
			LOG_INFO("[%p]: accepting packets from:%hu (flush:%d, r:%d, f:%d)", ctx, seqno, ctx->flush_seqno, ctx->synchro.required, ctx->synchro.first);
			ctx->ab_write = seqno-1;
			ctx->ab_read = ctx->ab_write + 1;
			ctx->skip = 0;
			ctx->flush_seqno = -1;
			ctx->playing = ctx->silence = true;
			ctx->synchro.first = false;
			ctx->resent_frames = ctx->silent_frames = 0;
			ctx->http_count = 0;
			encoder_open(ctx->encoder);
		} else {
			pthread_mutex_unlock(&ctx->ab_mutex);
			return;
		}
	}

//#define TEST_PACKET 0.2

#ifdef TEST_PACKET
	typedef struct {
		int count, failed;
		int last;
		bool active;
	} test_stat;

	static test_stat test_packet;
	test_packet.count++;
	double test_ratio = test_packet.count ? (double)test_packet.failed / test_packet.count : 0.0;
	if (test_ratio > TEST_PACKET * 1.025) test_packet.active = false;
	else if (test_ratio < TEST_PACKET * 0.975) test_packet.active = true;
	if (test_packet.active && ctx->http_count) {
		if ((rand() % (10 - test_packet.last)) && test_packet.last < 10) {
			test_packet.last++;
			test_packet.failed++;
			pthread_mutex_unlock(&ctx->ab_mutex);
			return;
		}
		test_packet.last = 0;
	}
	if (test_packet.count > 3500) test_packet.count = 0;
#endif

	// release as soon as one recent frame is received
	if (ctx->pause && seq_order(ctx->flush_seqno, seqno)) ctx->pause = false;

	if (seqno == (uint16_t) (ctx->ab_write + 1)) {
		// expected packet
		abuf = ctx->audio_buffer + BUFIDX(seqno);
		ctx->ab_write = seqno;
		LOG_SDEBUG("[%p]: packet expected seqno:%hu rtptime:%u (W:%hu R:%hu)", ctx, seqno, rtptime, ctx->ab_write, ctx->ab_read);
	} else if (seq_order(ctx->ab_write, seqno)) {
		// newer than expected
		if (ctx->latency && seq_order(ctx->latency / ctx->frame_size, seqno - ctx->ab_write - 1)) {
			// only get rtp latency-1 frames back (last one is seqno)
			LOG_WARN("[%p] too many missing frames %hu (%hu)", ctx, ctx->ab_write, seqno - ctx->ab_write - 1);
			ctx->ab_write = seqno - ctx->latency / ctx->frame_size;
		}
		if (ctx->delay && seq_order(ctx->delay, seqno - ctx->ab_read)) {
			// if ab_read is lagging more than http latency, advance it
			LOG_WARN("[%p] on hold for too long %hu (%hu)", ctx, ctx->ab_read, seqno - ctx->ab_read + 1);
			for (seq_t i = ctx->ab_read; seq_order(i, seqno - ctx->delay + 1); i++) ctx->audio_buffer[BUFIDX(i)].ready = false;
			ctx->ab_read = seqno - ctx->delay + 1;		
		}
		if (rtp_request_resend(ctx, ctx->ab_write + 1, seqno-1)) {
			uint32_t now = gettime_ms();
			for (seq_t i = ctx->ab_write + 1; seq_order(i, seqno); i++) {
				ctx->audio_buffer[BUFIDX(i)].rtptime = rtptime - (seqno-i)*ctx->frame_size;
				ctx->audio_buffer[BUFIDX(i)].last_resend = now;
			}
		}
		LOG_DEBUG("[%p]: packet newer seqno:%hu rtptime:%u (W:%hu R:%hu)", ctx, seqno, rtptime, ctx->ab_write, ctx->ab_read);
		abuf = ctx->audio_buffer + BUFIDX(seqno);
		ctx->ab_write = seqno;
	} else if (seq_order(ctx->ab_read, seqno + 1)) {
		// recovered packet, not yet sent
		abuf = ctx->audio_buffer + BUFIDX(seqno);
		LOG_DEBUG("[%p]: packet recovered seqno:%hu rtptime:%u (W:%hu R:%hu)", ctx, seqno, rtptime, ctx->ab_write, ctx->ab_read);
	} else {
		// too late
		LOG_INFO("[%p]: packet too late seqno:%hu rtptime:%u (W:%hu R:%hu)", ctx, seqno, rtptime, ctx->ab_write, ctx->ab_read);
	}

	if (!(ctx->in_frames++ & 0xfff) || (!(ctx->in_frames & 0x3f) && ctx->ab_write - ctx->ab_read > 24)) {
		LOG_INFO("[%p]: fill [level:%hu] [W:%hu R:%hu]", ctx, ctx->ab_write - ctx->ab_read + 1, ctx->ab_write, ctx->ab_read);
	}

	if (abuf) {
		alac_decode(ctx, abuf->data, data, len, &abuf->len);
		abuf->ready = 1;
		// this is the local rtptime when this frame is expected to play
		abuf->rtptime = rtptime;
#ifdef __RTP_STORE
		fwrite(data, len, 1, ctx->rtpIN);
		fwrite(abuf->data, abuf->len, 1, ctx->rtpOUT);
#endif
		if (ctx->silence && memcmp(abuf->data, ctx->silence_frame, abuf->len)) {
			ctx->event_cb(ctx->owner, RAOP_STREAMER_PLAY);
			ctx->silence = false;
			// if we have some metadata, just do a refresh (case of FLUSH not sending metadata)
			if (ctx->metadata.title) ctx->icy.updated = true;
		}
	}

	pthread_mutex_unlock(&ctx->ab_mutex);
}

/*---------------------------------------------------------------------------*/
static void *rtp_thread_func(void *arg) {
	fd_set fds;
	int i, sock = -1;
	int count = 0;
	bool ntp_sent;
	raopst_t *ctx = (raopst_t*) arg;

	for (i = 0; i < 3; i++) {
		if (ctx->rtp_sockets[i].sock > sock) sock = ctx->rtp_sockets[i].sock;
		// send synchro requests 3 times
		ntp_sent = rtp_request_timing(ctx);
	}

	while (ctx->running) {
		ssize_t plen;
		char type, packet[MAX_PACKET];
		socklen_t rtp_client_len = sizeof(struct sockaddr_storage);
		int idx = 0;
		char *pktp = packet;
		struct timeval timeout = {0, 50*1000};

		FD_ZERO(&fds);
		for (i = 0; i < 3; i++)	{ FD_SET(ctx->rtp_sockets[i].sock, &fds); }

		if (select(sock + 1, &fds, NULL, NULL, &timeout) <= 0) continue;

		for (i = 0; i < 3; i++)
			if (FD_ISSET(ctx->rtp_sockets[i].sock, &fds)) idx = i;

		plen = recvfrom(ctx->rtp_sockets[idx].sock, packet, sizeof(packet), 0, (struct sockaddr*) &ctx->rtp_host, &rtp_client_len);

		if (!ntp_sent) {
			LOG_WARN("[%p]: NTP request not sent yet", ctx);
			ntp_sent = rtp_request_timing(ctx);
		}

		if (plen < 0) continue;
		assert(plen <= MAX_PACKET);

		type = packet[1] & ~0x80;
		pktp = packet;

		switch (type) {
			seq_t seqno;
			unsigned rtptime;

			// re-sent packet
			case 0x56: {
				pktp += 4;
				plen -= 4;
			}

			// data packet
			case 0x60: {
				seqno = ntohs(*(uint16_t*)(pktp+2));
				rtptime = ntohl(*(uint32_t*)(pktp+4));

				// adjust pointer and length
				pktp += 12;
				plen -= 12;

				LOG_SDEBUG("[%p]: seqno:%hu rtp:%u (type: %x, first: %u)", ctx, seqno, rtptime, type, packet[1] & 0x80);

				// check if packet contains enough content to be reasonable
				if (plen < 16) break;

				if ((packet[1] & 0x80) && (type != 0x56)) {
					LOG_INFO("[%p]: 1st audio packet received %hu", ctx, seqno);
				}

				buffer_put_packet(ctx, seqno, rtptime, packet[1] & 0x80, pktp, plen);
				break;
			}

			// sync packet
			case 0x54: {
				uint32_t rtp_now_latency = ntohl(*(uint32_t*)(pktp+4));
				uint32_t rtp_now = ntohl(*(uint32_t*)(pktp+16));

				pthread_mutex_lock(&ctx->ab_mutex);

				// memorize that remote timing for when NTP adjustment arrives
				ctx->timing.rtp_remote = (((uint64_t)ntohl(*(uint32_t*)(pktp + 8))) << 32) + ntohl(*(uint32_t*)(pktp + 12));

				// re-align timestamp and expected local playback time
				if (!ctx->latency) ctx->latency = rtp_now - rtp_now_latency;
				ctx->synchro.rtp = rtp_now - ctx->latency;

				// now we are synced on RTP frames
				if ((ctx->synchro.status & RTP_SYNC) == 0) {
					ctx->synchro.status |= RTP_SYNC;
					LOG_INFO("[%p]: 1st RTP packet received", ctx);
				}

				// 1st sync packet received (signals a restart of playback)
				if (packet[0] & 0x10) {
					ctx->synchro.first = true;
					LOG_INFO("[%p]: 1st sync packet received", ctx);
				}

				// we can't adjust timing if we don't have NTP
				if (ctx->synchro.status & NTP_SYNC) {
					ctx->synchro.time = ctx->timing.local + (uint32_t)NTP2MS(ctx->timing.rtp_remote - ctx->timing.remote);
					LOG_DEBUG("[%p]: sync packet rtp_latency:%u rtp:%u remote ntp:%" PRIx64 ", local time % u(now: % u)",
						ctx, rtp_now_latency, rtp_now, ctx->timing.rtp_remote, ctx->synchro.time, gettime_ms());
				} else {
					LOG_INFO("[%p]: NTP not acquired yet", ctx);
				}

				pthread_mutex_unlock(&ctx->ab_mutex);

				if (!count--) {
					rtp_request_timing(ctx);
					count = 3;
				}
				break;
			}

			// NTP timing packet
			case 0x53: {
				uint64_t expected;
				int64_t delta = 0;
				uint32_t reference   = ntohl(*(uint32_t*)(pktp+12)); // only low 32 bits in our case
				uint64_t remote 	  =(((uint64_t) ntohl(*(uint32_t*)(pktp+16))) << 32) + ntohl(*(uint32_t*)(pktp+20));
				uint32_t roundtrip   = gettime_ms() - reference;

				// better discard sync packets when roundtrip is suspicious and get another one
				if (roundtrip > 100) {
					LOG_WARN("[%p]: discarding NTP roundtrip of %u ms", ctx, roundtrip);
					break;
				}

				/*
				  The expected elapsed remote time should be exactly the same as
				  elapsed local time between the two request, corrected by the
				  drifting
				*/
				expected = ctx->timing.remote + MS2NTP(reference - ctx->timing.local);

				ctx->timing.remote = remote;
				ctx->timing.local = reference;
				ctx->timing.count++;

				if (!ctx->timing.drift && (ctx->synchro.status & NTP_SYNC)) {
					delta = NTP2MS((int64_t) expected - (int64_t) ctx->timing.remote);
					ctx->timing.gap_sum += delta;

					pthread_mutex_lock(&ctx->ab_mutex);

					/*
					 if expected time is more than remote, then our time is
					 running faster and we are transmitting frames too quickly,
					 so we'll run out of frames, need to add one
					*/
					if (ctx->timing.gap_sum > GAP_THRES && ctx->timing.gap_count++ > GAP_COUNT) {
						LOG_INFO("[%p]: Sending packets too fast %" PRId64 " [W:% hu R : % hu]", ctx, ctx->timing.gap_sum, ctx->ab_write, ctx->ab_read);
						ctx->ab_read--;
						ctx->audio_buffer[BUFIDX(ctx->ab_read)].ready = 1;
						ctx->timing.gap_sum -= GAP_THRES;
						ctx->timing.gap_adjust -= GAP_THRES;
					/*
					 if expected time is less than remote, then our time is
					 running slower and we are transmitting frames too slowly,
					 so we'll overflow frames buffer, need to remove one
					*/
					} else if (ctx->timing.gap_sum < -GAP_THRES && ctx->timing.gap_count++ > GAP_COUNT) {
						if (seq_order(ctx->ab_read, ctx->ab_write)) {
							ctx->audio_buffer[BUFIDX(ctx->ab_read)].ready = 0;
							ctx->ab_read++;
						} else ctx->skip++;
						ctx->timing.gap_sum += GAP_THRES;
						ctx->timing.gap_adjust += GAP_THRES;
						LOG_INFO("[%p]: Sending packets too slow %" PRId64 " (skip: % d)[W:% hu R : % hu]", ctx, ctx->timing.gap_sum, ctx->skip, ctx->ab_write, ctx->ab_read);
					}

					if (llabs(ctx->timing.gap_sum) < 8) ctx->timing.gap_count = 0;

					pthread_mutex_unlock(&ctx->ab_mutex);
				}

				// re-adjust the synchro time in case it could not have been done by first RTP because NTP was missing
				ctx->synchro.time = ctx->timing.local + (uint32_t)NTP2MS(ctx->timing.rtp_remote - ctx->timing.remote);

				// now we are synced on NTP (mutex not needed)
				if ((ctx->synchro.status & NTP_SYNC) == 0) {
					LOG_INFO("[%p]: 1st NTP packet received", ctx);
					ctx->synchro.status |= NTP_SYNC;
				}

				LOG_DEBUG("[%p]: Timing references local:%" PRIu64 ", remote: %" PRIx64 " (delta : %" PRId64 ", sum : %" PRId64 ", adjust : %" PRId64 ", gaps : % d)",
						  ctx, ctx->timing.local, ctx->timing.remote, delta, ctx->timing.gap_sum, ctx->timing.gap_adjust, ctx->timing.gap_count);
				break;
			}
		}
	}

	LOG_INFO("[%p]: terminating", ctx);

	return NULL;
}

/*---------------------------------------------------------------------------*/
static bool rtp_request_timing(raopst_t *ctx) {
	unsigned char req[32];
	uint32_t now = gettime_ms();
	int i;
	struct sockaddr_in host;

	LOG_DEBUG("[%p]: timing request now:%u (port: %hu)", ctx, now, ctx->rtp_sockets[TIMING].rport);

	req[0] = 0x80;
	req[1] = 0x52|0x80;
	*(uint16_t*)(req+2) = htons(7);
	*(uint32_t*)(req+4) = htonl(0);  // dummy
	for (i = 0; i < 16; i++) req[i+8] = 0;
	*(uint32_t*)(req+24) = 0;
	*(uint32_t*)(req+28) = htonl(now); // this is not a real NTP, but a 32 ms counter in the low part of the NTP

	if (ctx->peer.s_addr != INADDR_ANY) {
		host.sin_family = AF_INET;
		host.sin_addr =	ctx->peer;
	} else host = ctx->rtp_host;

	// no address from sender, need to wait for 1st packet to be received
	if (host.sin_addr.s_addr == INADDR_ANY) return false;

	host.sin_port = htons(ctx->rtp_sockets[TIMING].rport);

	if (sizeof(req) != sendto(ctx->rtp_sockets[TIMING].sock, req, sizeof(req), 0, (struct sockaddr*) &host, sizeof(host))) {
		LOG_WARN("[%p]: SENDTO failed (%s)", ctx, strerror(errno));
	}

	return true;
}

/*---------------------------------------------------------------------------*/
static bool rtp_request_resend(raopst_t *ctx, seq_t first, seq_t last) {
	unsigned char req[8];    // *not* a standard RTCP NACK

	// do not request silly ranges (happens in case of network large blackouts)
	if (seq_order(last, first) || last - first > BUFFER_FRAMES / 2) return false;

	ctx->resent_frames += (seq_t) (last - first) + 1;

	LOG_DEBUG("resend request [W:%hu R:%hu first=%hu last=%hu]", ctx->ab_write, ctx->ab_read, first, last);

	req[0] = 0x80;
	req[1] = 0x55|0x80;  // Apple 'resend'
	*(uint16_t*)(req+2) = htons(1);  // our seqnum
	*(uint16_t*)(req+4) = htons(first);  // missed seqnum
	*(uint16_t*)(req+6) = htons((seq_t) (last-first)+1);  // count

	ctx->rtp_host.sin_port = htons(ctx->rtp_sockets[CONTROL].rport);

	if (sizeof(req) != sendto(ctx->rtp_sockets[CONTROL].sock, req, sizeof(req), 0, (struct sockaddr*) &ctx->rtp_host, sizeof(ctx->rtp_host))) {
		LOG_WARN("[%p]: SENDTO failed (%s)", ctx, strerror(errno));
	}

	return true;
}

/*---------------------------------------------------------------------------*/
// get the next frame, when available. return 0 if underrun/stream reset.
static short *_buffer_get_frame(raopst_t *ctx, size_t *bytes) {
	// no frame (even silence) when not playing and not synchronized
	if (!ctx->playing || ctx->synchro.status != (RTP_SYNC | NTP_SYNC)) return NULL;

	// send silence if required to create enough buffering (want countdown to happen)
	if ((ctx->silence_count && ctx->silence_count--) || ctx->pause)	{
		*bytes = ctx->frame_size * 4;
		return (short*) ctx->silence_frame;
	}

	// skip frames if we are running late and skip could not be done in SYNC
	while (ctx->skip && seq_order(ctx->ab_read, ctx->ab_write)) {
		ctx->audio_buffer[BUFIDX(ctx->ab_read)].ready = 0;
		ctx->ab_read++;
		ctx->skip--;
		LOG_INFO("[%p]: Sending packets too slow (skip: %d) [W:%hu R:%hu]", ctx, ctx->skip, ctx->ab_write, ctx->ab_read);
	}

	uint32_t now = gettime_ms();
	short buf_fill = ctx->ab_write - ctx->ab_read + 1;

	// in case of overrun, just reset read pointer to a sane value
	if (buf_fill >= BUFFER_FRAMES) {
		LOG_WARN("[%p]: Buffer overrun %hu", ctx, buf_fill);
		ctx->ab_read = ctx->ab_write - (BUFFER_FRAMES - 64);
		buf_fill = ctx->ab_write - ctx->ab_read + 1;
	}

	abuf_t* curframe = ctx->audio_buffer + BUFIDX(ctx->ab_read);

	// try to request resend missing packet in order, explore up to 64 frames
	for (int step = max(buf_fill / 64, 1), i = 0, first = 0; seq_order(ctx->ab_read + i, ctx->ab_write); i += step) {
		abuf_t* frame = ctx->audio_buffer + BUFIDX(ctx->ab_read + i);

		// stop when we reach a ready frame or a recent pending resend
		if (first && (frame->ready || now - frame->last_resend <= RESEND_TO)) {
			if (!rtp_request_resend(ctx, first, ctx->ab_read + i - 1)) break;
			first = 0;
			i += step - 1;
		} else if (!frame->ready && now - frame->last_resend > RESEND_TO) {
			if (!first) first = ctx->ab_read + i;
			frame->last_resend = now;
		}
	}

	// use and update previous frame when buffer is empty (previous is always valid)
	if (!buf_fill) curframe->rtptime = ctx->audio_buffer[BUFIDX(ctx->ab_read - 1)].rtptime + ctx->frame_size;

	// watch out for 32 bits overflow
	uint32_t playtime = ctx->synchro.time + (((int32_t)(curframe->rtptime - ctx->synchro.rtp)) * 1000) / 44100;
	LOG_SDEBUG("playtime %u %d [W:%hu R:%hu] %d", playtime, playtime - now, ctx->ab_write, ctx->ab_read, curframe->ready);

	// wait if frame is not ready and we have time or if we have no frame and are not allowed to fill
	if (!curframe->ready && (now < playtime || (!buf_fill && !ctx->http_fill))) {
		LOG_SDEBUG("[%p]: waiting (fill:%hd, W:%hu R:%hu) now:%u, playtime:%u, wait:%d", ctx, buf_fill, ctx->ab_write, ctx->ab_read, now, playtime, playtime - now);
		return NULL;
	}

	/* I'm not 100% that all cases where audio_buffer should be reset are handled so there is a chance 
	 * that we end-up here with curframe->ready but from an old frame. To avoid that to create a mess
	 * we'll verify first that buffer is empty. We can be there anyway if case we do filling */
	if (!buf_fill) {
		// when silence is inserted at the top, need to move write pointer as well
		ctx->ab_write++;
		ctx->filled_frames++;
		curframe->ready = 0;
	} else if (!curframe->ready) {
		ctx->silent_frames++;
	} else {
		LOG_SDEBUG("[%p]: prepared frame (fill:%hd, W:%hu R:%hu)", ctx, buf_fill - 1, ctx->ab_write, ctx->ab_read);
	}

	if (!curframe->ready) {
		LOG_DEBUG("[%p]: created zero frame at %d (W:%hu R:%hu)", ctx, now - playtime, ctx->ab_write, ctx->ab_read);
		memset(curframe->data, 0, ctx->frame_size * 4);
		*bytes = ctx->frame_size * 4;
	} else {
		*bytes = curframe->len;
		curframe->ready = 0;
	}

	// a bit of logging from time to time or when we have a network blackout
	if (!(ctx->out_frames++ & 0xfff) || (!(ctx->out_frames & 0x3f) && buf_fill >= 25) || ctx->filled_frames > 100) {
		LOG_INFO("[%p]: drain [level:%hd gap:%d] [W:%hu R:%hu] [R:%u S:%u F:%u]",
					ctx, buf_fill-1, playtime - now, ctx->ab_write, ctx->ab_read,
					ctx->resent_frames, ctx->silent_frames, ctx->filled_frames);
		ctx->filled_frames = 0;
	}

	ctx->ab_read++;
	return curframe->data;
}

/*---------------------------------------------------------------------------*/
int send_data(bool chunked, int sock, const void *data, int size, int flags) {
	if (!chunked) return send(sock, data, size, flags);

	char chunk[16];
	itoa(size, chunk, 16);
	strcat(chunk, "\r\n");

	send(sock, chunk, strlen(chunk), flags);
	size = send(sock, data, size, flags);
	send(sock, "\r\n", 2, flags);

	return size;
}

/*---------------------------------------------------------------------------*/
static void *http_thread_func(void *arg) {
	int frame_count = 0;
	raopst_t *ctx = (raopst_t*) arg;
	int sock = -1;
	struct timeval timeout = { 0, 0 };

	while (ctx->running) {
		fd_set rfds;

		if (sock == -1) {
			struct timeval timeout = {0, 50*1000};

			FD_ZERO(&rfds);
			FD_SET(ctx->http_listener, &rfds);

			if (select(ctx->http_listener + 1, &rfds, NULL, NULL, &timeout) > 0) {
				sock = accept(ctx->http_listener, NULL, NULL);
			}

			if (sock != -1 && ctx->running) {
				int on = 1;
				setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on));
				LOG_INFO("[%p]: got HTTP connection %u", ctx, sock);
			} else continue;
		}

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		int n = select(sock + 1, &rfds, NULL, NULL, &timeout);
		bool res = true;

		pthread_mutex_lock(&ctx->ab_mutex);

		if (n > 0) {
			res = handle_http(ctx, sock);
			ctx->http_ready = res;

			// only send silence when it's the first GET (or after a flush)
			if (!ctx->http_count) {
				// send just the right amount of silence (ab_xxx are always accurate)
				short buf_fill = ctx->ab_write - ctx->ab_read + 1;
				if (buf_fill >= 0) ctx->silence_count = ctx->delay - min(ctx->delay, buf_fill);
				else ctx->silence_count = 0;

				LOG_INFO("[%p]: sending %d silence frames", ctx, ctx->silence_count);
			}
		}

		// terminate connection if required by HTTP peer
		if (n < 0 || !res || ctx->close_socket) {
			LOG_INFO("HTTP close %u", sock);
			closesocket(sock);
			sock = -1;
			ctx->close_socket = ctx->http_ready = false;
		}

		int16_t* pcm;
		size_t bytes;

		// wait for session to be ready before sending (no need for mutex)
		if (ctx->http_ready && (pcm = _buffer_get_frame(ctx, &bytes)) != NULL) {
			size_t frames = bytes / 4;
			uint8_t* data = encoder_encode(ctx->encoder, pcm, frames, &bytes);

			if (bytes) {
				uint32_t space, gap = gettime_ms();
				int offset;

#ifdef __RTP_STORE
				fwrite(inbuf, len, 1, ctx->httpOUT);
#endif
				// store data for a potential re-send
				space = min(bytes, CACHE_SIZE - (ctx->http_count % CACHE_SIZE));
				memcpy(ctx->http_cache + (ctx->http_count % CACHE_SIZE), data, space);
				memcpy(ctx->http_cache, data + space, bytes - space);
				ctx->http_count += bytes;

				// check if ICY sending is active (len < ICY_INTERVAL)
				if (ctx->icy.active && bytes > ctx->icy.remain) {
					int len_16 = 0;
					char buffer[ICY_LEN_MAX];

					if (ctx->icy.updated) {
						char *format;

						// there is room for 1 extra byte at the beginning for length
						if (ctx->metadata.artwork) format = "NStreamTitle='%s%s%s';StreamURL='%s';";
						else format = "NStreamTitle='%s%s%s';";
						int len = sprintf(buffer, format, ctx->metadata.artist,
										 ctx->metadata.artist ? " - " : "",
										 ctx->metadata.title, ctx->metadata.artwork) - 1;
						LOG_INFO("[%p]: ICY update %s", ctx, buffer + 1);
						len_16 = (len + 15) / 16;
						memset(buffer + len + 1, 0, len_16 * 16 - len);
						ctx->icy.updated = false;
						raopsr_metadata_free(&ctx->metadata);
					}

					buffer[0] = len_16;

					// release mutex here as send might take a while
					pthread_mutex_unlock(&ctx->ab_mutex);

					// send remaining data first
					offset = ctx->icy.remain;
					if (offset) send_data(ctx->http_length == -3, sock, data, offset, 0);
					bytes -= offset;

					// then send icy data
					send_data(ctx->http_length == -3, sock, buffer, len_16 * 16 + 1, 0);
					ctx->icy.remain = ctx->icy.interval;

					LOG_SDEBUG("[%p]: ICY checked %u", ctx, ctx->icy.remain);
				} else {
					offset = 0;
					pthread_mutex_unlock(&ctx->ab_mutex);
				}

				LOG_SDEBUG("[%p]: HTTP sent frame count:%u bytes:%u (W:%hu R:%hu)", ctx, frame_count++, bytes + offset, ctx->ab_write, ctx->ab_read);
				ssize_t sent = send_data(ctx->http_length == -3, sock, data + offset , bytes, 0);

				// update remaining count with desired length
				if (ctx->icy.active) ctx->icy.remain -= bytes;

				gap = gettime_ms() - gap;

				if (gap > 100) {
					LOG_WARN("[%p]: spent %u ms in send for %u bytes (sent %zd)!", ctx, gap, bytes, sent);
				}

				if (sent != bytes) {
					LOG_WARN("[%p]: HTTP send() unexpected response: %li (data=%i): %s", ctx, (long int) sent, bytes, strerror(errno));
				}
			} else pthread_mutex_unlock(&ctx->ab_mutex);

			// no wait if we have more to send (catch-up) or just 1 frame in pause mode
			timeout.tv_usec = ctx->pause ? (ctx->frame_size*1000000)/44100 : 0;
		} else {
			// nothing to send, so probably can wait 2 frame unless paused
			timeout.tv_usec = (2*ctx->frame_size*1000000)/44100;
			pthread_mutex_unlock(&ctx->ab_mutex);
		}
	}

	if (sock != -1) shutdown_socket(sock);

	LOG_INFO("[%p]: terminating", ctx);
	return NULL;
}

/*----------------------------------------------------------------------------*/
static bool handle_http(raopst_t *ctx, int sock) {
	char *body = NULL, method[16] = "", proto[16] = "", *str, *head = NULL;
	key_data_t headers[64], resp[16] = { { NULL, NULL } };
	size_t offset = 0;
	int len;

	if (!http_parse(sock, method, NULL, proto, headers, &body, &len)) return false;
	bool HTTP_11 = strstr(proto, "HTTP/1.1") != NULL;

	if (*loglevel >= lINFO) {
		char *p = kd_dump(headers);
		LOG_INFO("[%p]: received %s %s\n%s", ctx, method, proto, p);
		NFREE(p);
	}

	kd_add(resp, "Server", "HairTunes");
	kd_add(resp, "Content-Type", encoder_mimetype(ctx->encoder));

	// is there a range request (chromecast non-compliance to HTTP !!!)
	if (ctx->range && ((str = kd_lookup(headers, "Range")) != NULL)) {
#if WIN
		sscanf(str, "bytes=%u", &offset);
#else
		sscanf(str, "bytes=%zu", &offset);
#endif	
		if (offset) {
			// try to find the position in the memorized data
			offset = (ctx->http_count && ctx->http_count > CACHE_SIZE) ? min(offset, ctx->http_count - CACHE_SIZE - 1) : 0;
			head = (ctx->http_length == -3 && HTTP_11) ? "HTTP/1.1 206 Partial Content" : "HTTP/1.0 206 Partial Content";
			kd_vadd(resp, "Content-Range", "bytes %zu-%zu/*", offset, ctx->http_count);
		}
	}

	// check if add ICY metadata is needed (only on live stream)
	if (ctx->icy.enabled &&	((str = kd_lookup(headers, "Icy-MetaData")) != NULL) && atoi(str)) {
		kd_vadd(resp, "icy-metaint", "%u", ctx->icy.interval);
		ctx->icy.remain = ctx->icy.interval;
		ctx->icy.active = true;
	} else ctx->icy.active = false;

	// let owner modify HTTP response if needed
	if (ctx->http_cb) ctx->http_cb(ctx->owner, headers, resp);

	if (ctx->http_length == -3 && HTTP_11) {
		char *value = kd_lookup(headers, "Connection");
		if (value && (!strcasecmp(value, "close") || !strcasecmp(value,"keep-alive"))) kd_add(resp, "Connection", value);
		else kd_add(resp, "Connection", "close");
		kd_add(resp, "Transfer-Encoding", "chunked");
		str = http_send(sock, head ? head : "HTTP/1.1 200 OK", resp);
	} else {
		// content-length is only for current payload, so ignore it with range 
		if (ctx->http_length > 0 && !offset) kd_vadd(resp, "Content-Length", "%d", ctx->http_length);
		kd_add(resp, "Connection", "close");
		str = http_send(sock, head ? head : "HTTP/1.0 200 OK", resp);
	}

	LOG_INFO("[%p]: responding: %s", ctx, str);

	NFREE(body);
	NFREE(str);
	kd_free(resp);
	kd_free(headers);

	// nothing else to do if this is a HEAD request
	if (strstr(method, "HEAD")) return false;

	// need to re-send the range or restart from as far as possible on simple GET
	if (offset || (ctx->http_count && ctx->http_count <= CACHE_SIZE)) {
		size_t count = 0;

		LOG_INFO("[%p] re-sending bytes %zu-%zu", ctx, offset, ctx->http_count);
		ctx->silence_count = 0;
		while (count != ctx->http_count - offset) {
			size_t bytes = ctx->icy.active ? ctx->icy.remain : 16384;
			int sent;

			bytes = min(bytes, ctx->http_count - offset - count);
			sent = send_data(ctx->http_length == -3, sock, ctx->http_cache + ((offset + count) % CACHE_SIZE), bytes, 0);

			if (sent < 0) {
				LOG_ERROR("[%p]: error re-sending range %u", ctx, offset);
				break;
			}

			count += sent;

			// send ICY data if needed
			if (ctx->icy.active) {
				ctx->icy.remain -= sent;
				if (!ctx->icy.remain) {
					send_data(ctx->http_length == -3, sock, "", 1, 0);
					ctx->icy.remain = ctx->icy.interval;
				}
			}
		}
	}

	return true;
}
