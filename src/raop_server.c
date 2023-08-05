/*
 *  RAOP server: control an AirPlay-1 client
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 *	See LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

#include "platform.h"
#include "mdnssvc.h"
#include "mdnssd.h"
#include "cross_util.h"
#include "base64.h"
#include "raop_server.h"
#include "raop_streamer.h"
#include "dmap_parser.h"

#include "cross_net.h"
#include "cross_log.h"

typedef struct raopsr_s {
	struct mdns_service *svc;
	struct mdnsd *svr;
	struct in_addr host;	// IP of bridge
	short unsigned port;    // RTSP port for AirPlay
	int sock;               // socket of the above
	short unsigned hport; 	// HTTP port of audio server where CC can "GET" audio
	struct in_addr peer;	// IP of the iDevice (airplay sender)
	char *latencies;
	bool running;
	raopst_encode_t encode;
	bool drift;
	bool flush;
	pthread_t thread, search_thread;
	unsigned char mac[6];
	struct {
		char *aesiv, *aeskey;
		char *fmtp;
	} rtsp;
	struct raopst_s *ht;
	raopsr_cb_t	raop_cb;
	raop_http_cb_t http_cb;
	raopsr_metadata_t metadata;
	bool flushedArtwork;
	int sequence;
	struct {
		char				DACPid[32], id[32];
		struct in_addr		host;
		uint16_t				port;
		struct mdnssd_handle_s *handle;
	} active_remote;
	void *owner;
	struct {
		uint16_t base, range;
	} ports;
	int http_length;
} raopsr_t;

extern log_level	raop_loglevel;
static log_level 	*loglevel = &raop_loglevel;

static void*	rtsp_thread(void *arg);
static bool 	handle_rtsp(raopsr_t *ctx, int sock);

static char*	rsa_apply(unsigned char *input, int inlen, int *outlen, int mode);
static int  	base64_pad(char *src, char **padded);
static void 	event_cb(void *owner, raopst_event_t event);
static void 	http_cb(void *owner, struct key_data_s *headers, struct key_data_s *response);
static void* 	search_remote(void *args);

extern char private_key[];

enum { RSA_MODE_KEY, RSA_MODE_AUTH };

static void on_dmap_string(void *ctx, const char *code, const char *name, const char *buf, size_t len);

/*----------------------------------------------------------------------------*/
struct raopsr_s *raopsr_create(struct in_addr host, struct mdnsd *svr, char *name,
						char *model, unsigned char mac[6], char *codec, bool metadata,
						bool drift,	bool flush, char *latencies, void *owner,
						raopsr_cb_t raop_cb, raop_http_cb_t http_cb,
						unsigned short port_base, unsigned short port_range,
						int http_length ) {
	struct raopsr_s *ctx = malloc(sizeof(struct raopsr_s));
	char *id;
	int i;
	struct {
		unsigned short count, offset;
	} port = { 0 };

	char *txt[] = { NULL, "tp=UDP", "sm=false", "sv=false", "ek=1",
					"et=0,1", "md=0,1,2", "cn=0,1", "ch=2",
					"ss=16", "sr=44100", "vn=3", "txtvers=1",
					NULL };

	if (!ctx) return NULL;

	// make sure we have a clean context
	memset(ctx, 0, sizeof(raopsr_t));

	ctx->http_length = http_length;
	ctx->ports.base = port_base;
	ctx->ports.range = port_range;
	ctx->host = host;
	ctx->raop_cb = raop_cb;
	ctx->http_cb = http_cb;
	ctx->flush = flush;
	ctx->latencies = strdup(latencies);
	ctx->owner = owner;
	ctx->drift = drift;
	if (!strcasecmp(codec, "pcm")) ctx->encode.codec = CODEC_PCM;
	else if (!strcasecmp(codec, "wav")) ctx->encode.codec = CODEC_WAV;
	else if (strcasestr(codec, "mp3")) {
		ctx->encode.codec = CODEC_MP3;
		ctx->encode.mp3.icy = metadata;
		if (strchr(codec, ':')) ctx->encode.mp3.bitrate = atoi(strchr(codec, ':') + 1);
	} else {
		ctx->encode.codec = CODEC_FLAC;
		if (strchr(codec, ':')) ctx->encode.flac.level = atoi(strchr(codec, ':') + 1);
	}

	// find a free port
	if (!port_base) port_range = 1;
	port.offset = rand() % port_range;

	do {
		ctx->port = port_base + ((port.offset + port.count++) % port_range);
		ctx->sock = bind_socket(ctx->host, &ctx->port, SOCK_STREAM);
	} while (ctx->sock < 0 && port.count < port_range);

	// then listen for RTSP incoming connections
	if (ctx->sock < 0 || listen(ctx->sock, 1)) {
		LOG_ERROR("Cannot bind or listen RTSP listener: %s", strerror(errno));
		closesocket(ctx->sock);
		free(ctx);
		return NULL;
	}

	// set model
	(void)!asprintf(&(txt[0]), "am=%s", model);
	id = malloc(strlen(name) + 12 + 1 + 1);

	memcpy(ctx->mac, mac, 6);

	for (i = 0; i < 6; i++) sprintf(id + i*2, "%02X", mac[i]);

	// mDNS instance name length cannot be more than 63
	sprintf(id + 12, "@%s", name);

	// Windows snprintf does not add NULL if string is larger than n ...
	if (strlen(id) > 63) id[63] = '\0';

	ctx->svr = svr;
	ctx->svc = mdnsd_register_svc(svr, id, "_raop._tcp.local", ctx->port, NULL, (const char**) txt);

	free(txt[0]);
	free(id);

	ctx->running = true;
	pthread_create(&ctx->thread, NULL, &rtsp_thread, ctx);

	return ctx;
}

/*----------------------------------------------------------------------------*/
void raopsr_update(struct raopsr_s *ctx, char *name, char *model) {
	char *txt[] = { NULL, "tp=UDP", "sm=false", "sv=false", "ek=1",
					"et=0,1", "md=0,1,2", "cn=0,1", "ch=2",
					"ss=16", "sr=44100", "vn=3", "txtvers=1",
					NULL };

	if (!ctx) return;

	mdns_service_remove(ctx->svr, ctx->svc);

	// set model
	(void)!asprintf(&(txt[0]), "am=%s", model);
	char* id = malloc(strlen(name) + 12 + 1 + 1);
	for (int i = 0; i < 6; i++) sprintf(id + i*2, "%02X", ctx->mac[i]);
	// mDNS instance name length cannot be more than 63
	sprintf(id + 12, "@%s", name);
	// Windows snprintf does not add NULL if string is larger than n ...
	if (strlen(id) > 63) id[63] = '\0';

	ctx->svc = mdnsd_register_svc(ctx->svr, id, "_raop._tcp.local", ctx->port, NULL, (const char**) txt);

	free(txt[0]);
	free(id);
}

/*----------------------------------------------------------------------------*/
void raopsr_delete(struct raopsr_s *ctx) {
	if (!ctx) return;

	ctx->running = false;
	pthread_join(ctx->thread, NULL);

	raopsr_metadata_free(&ctx->metadata);
	raopst_end(ctx->ht);

#if WIN
	shutdown(ctx->sock, SD_BOTH);
#else
	shutdown(ctx->sock, SHUT_RDWR);
#endif
	closesocket(ctx->sock);

	// terminate search, but do not reclaim memory of pthread if never launched
	if (ctx->active_remote.handle) {
		mdnssd_close(ctx->active_remote.handle);
		pthread_join(ctx->search_thread, NULL);
	}

	NFREE(ctx->rtsp.aeskey);
	NFREE(ctx->rtsp.aesiv);
	NFREE(ctx->rtsp.fmtp);
	free(ctx->latencies);

	mdns_service_remove(ctx->svr, ctx->svc);

	free(ctx);
}


/*----------------------------------------------------------------------------*/
void  raopsr_notify(struct raopsr_s *ctx, raopsr_event_t event, void *param) {
	struct sockaddr_in addr;
	char *command = NULL;

	if (!ctx) return;

	switch(event) {
		case RAOP_PAUSE:
			command = strdup("pause");
			break;
		case RAOP_PLAY:
			command = strdup("play");
			break;
		case RAOP_STOP:
			command = strdup("stop");
			break;
		case RAOP_VOLUME: {
			double Volume = *((double*) param);

			Volume = Volume ? (Volume - 1) * 30 : -144;
			(void)!asprintf(&command,"setproperty?dmcp.device-volume=%0.4lf", Volume);
			break;
		}
		default:
			break;
	}

	// no command to send to remote or no remote found yet
	if (!command || !ctx->active_remote.port) {

		NFREE(command);

		return;

	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = ctx->active_remote.host;
	addr.sin_port = htons(ctx->active_remote.port);

	if (!connect(sock, (struct sockaddr*) &addr, sizeof(addr))) {
		char *method, *buf, resp[512] = "";
		int len;
		key_data_t headers[4] = { {NULL, NULL} };

		(void)!asprintf(&method, "GET /ctrl-int/1/%s HTTP/1.0", command);
		kd_add(headers, "Active-Remote", ctx->active_remote.id);
		kd_add(headers, "Connection", "close");

		buf = http_send(sock, method, headers);
		len = recv(sock, resp, 512, 0);
		if (len > 0) resp[len-1] = '\0';
		LOG_INFO("[%p]: sending airplay remote\n%s<== received ==>\n%s", ctx, buf, resp);

		NFREE(method);
		NFREE(buf);
		kd_free(headers);
	}

	free(command);

	closesocket(sock);
}

/*----------------------------------------------------------------------------*/
void raopsr_metadata_free(raopsr_metadata_t* data) {
	NFREE(data->title);
	NFREE(data->artist);
	NFREE(data->album);
	NFREE(data->artwork);
}

/*----------------------------------------------------------------------------*/
void raopsr_metadata_copy(raopsr_metadata_t* dst, raopsr_metadata_t* src) {
	if (src->title) dst->title = strdup(src->title);
	if (src->artist) dst->artist = strdup(src->artist);
	if (src->album) dst->album = strdup(src->album);
	if (src->artwork) dst->artwork = strdup(src->artwork);
}

/*----------------------------------------------------------------------------*/
static void *rtsp_thread(void *arg) {
	raopsr_t *ctx = (raopsr_t*) arg;
	int  sock = -1;

	while (ctx->running) {
		fd_set rfds;
		struct timeval timeout = {0, 100*1000};
		int n;
		bool res = false;

		if (sock == -1) {
			struct sockaddr_in peer;
			socklen_t addrlen = sizeof(struct sockaddr_in);
			struct timeval timeout = { 0, 100 * 1000 };

			FD_ZERO(&rfds);
			FD_SET(ctx->sock, &rfds);

			if (select(ctx->sock + 1, &rfds, NULL, NULL, &timeout) > 0) {
				sock = accept(ctx->sock, (struct sockaddr*)&peer, &addrlen);
				ctx->peer.s_addr = peer.sin_addr.s_addr;
			}

			if (sock != -1 && ctx->running) {
				LOG_INFO("got RTSP connection %u", sock);
			} else continue;
		}

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		n = select(sock + 1, &rfds, NULL, NULL, &timeout);

		if (!n) continue;

		if (n > 0) res = handle_rtsp(ctx, sock);

		if (n < 0 || !res) {
			closesocket(sock);
			LOG_INFO("RTSP close %u", sock);
			sock = -1;
		}
	}

	if (sock != -1) closesocket(sock);

	return NULL;
}


/*----------------------------------------------------------------------------*/
static bool handle_rtsp(raopsr_t *ctx, int sock)
{
	char *buf = NULL, *body = NULL, method[16] = "";
	key_data_t headers[64], resp[16] = { {NULL, NULL} };
	int len;
	bool success = true;

	if (!http_parse(sock, method, NULL, NULL, headers, &body, &len)) {
		NFREE(body);
		kd_free(headers);
		return false;
	}

	if (strcmp(method, "OPTIONS")) {
		LOG_INFO("[%p]: received %s", ctx, method);
	}

	if ((buf = kd_lookup(headers, "Apple-Challenge")) != NULL) {
		char *buf_pad, *p, *data_b64 = NULL, data[32];

		LOG_INFO("[%p]: challenge %s", ctx, buf);

		// need to pad the base64 string as apple device don't
		base64_pad(buf, &buf_pad);

		p = data + min(base64_decode(buf_pad, data), 32-10);
		p = (char*) memcpy(p, &ctx->host, 4) + 4;
		p = (char*) memcpy(p, ctx->mac, 6) + 6;
		memset(p, 0, 32 - (p - data));
		int n;
		p = rsa_apply((unsigned char*) data, 32, &n, RSA_MODE_AUTH);
		n = base64_encode(p, n, &data_b64);

		// remove padding as well (seems to be optional now)
		for (n = strlen(data_b64) - 1; n > 0 && data_b64[n] == '='; data_b64[n--] = '\0');

		kd_add(resp, "Apple-Response", data_b64);

		NFREE(p);
		NFREE(buf_pad);
		NFREE(data_b64);
	}

	if (!strcmp(method, "OPTIONS")) {
		kd_add(resp, "Public", "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER");
	} else if (!strcmp(method, "ANNOUNCE") && body) {
		char *padded, *p;

		NFREE(ctx->rtsp.aeskey);
		NFREE(ctx->rtsp.aesiv);
		NFREE(ctx->rtsp.fmtp);

		if ((p = strcasestr(body, "rsaaeskey")) != NULL) {
			unsigned char *aeskey;
			int len, outlen;

			p = strextract(p, ":", "\r\n");
			base64_pad(p, &padded);
			aeskey = malloc(strlen(padded));
			len = base64_decode(padded, aeskey);
			ctx->rtsp.aeskey = rsa_apply(aeskey, len, &outlen, RSA_MODE_KEY);

			NFREE(p);
			NFREE(aeskey);
			NFREE(padded);
		}

		if ((p = strcasestr(body, "aesiv")) != NULL) {
			p = strextract(p, ":", "\r\n");
			base64_pad(p, &padded);
			ctx->rtsp.aesiv = malloc(strlen(padded));
			base64_decode(padded, ctx->rtsp.aesiv);

			NFREE(p);
			NFREE(padded);
		}

		if ((p = strcasestr(body, "fmtp")) != NULL) {
			p = strextract(p, ":", "\r\n");
			ctx->rtsp.fmtp = strdup(p);
			NFREE(p);
		}

		// on announce, search remote
		if ((buf = kd_lookup(headers, "DACP-ID")) != NULL) strcpy(ctx->active_remote.DACPid, buf);
		if ((buf = kd_lookup(headers, "Active-Remote")) != NULL) strcpy(ctx->active_remote.id, buf);

		ctx->active_remote.handle = mdnssd_init(false, ctx->host, true);
		pthread_create(&ctx->search_thread, NULL, &search_remote, ctx);

	} else if (!strcmp(method, "SETUP") && ((buf = kd_lookup(headers, "Transport")) != NULL)) {
		char *p;
		raopst_resp_t ht;
		short unsigned tport = 0, cport = 0;

		if ((p = strcasestr(buf, "timing_port")) != NULL) sscanf(p, "%*[^=]=%hu", &tport);
		if ((p = strcasestr(buf, "control_port")) != NULL) sscanf(p, "%*[^=]=%hu", &cport);

		ht = raopst_init(ctx->host, ctx->peer, ctx->encode, false, ctx->drift, true, ctx->latencies,
							ctx->rtsp.aeskey, ctx->rtsp.aesiv, ctx->rtsp.fmtp,
							cport, tport, ctx, event_cb, http_cb, ctx->ports.base,
							ctx->ports.range, ctx->http_length);

		ctx->hport = ht.hport;
		ctx->ht = ht.ctx;
		ctx->flushedArtwork = true;

		if ((cport * tport * ht.cport * ht.tport * ht.aport * ht.hport) != 0 && ht.ctx) {
			char *transport;
			(void) !asprintf(&transport, "RTP/AVP/UDP;unicast;mode=record;control_port=%u;timing_port=%u;server_port=%u", ht.cport, ht.tport, ht.aport);
			LOG_DEBUG("[%p]: http=(%hu) audio=(%hu:%hu), timing=(%hu:%hu), control=(%hu:%hu)", ctx, ht.hport, 0, ht.aport, tport, ht.tport, cport, ht.cport);
			kd_add(resp, "Transport", transport);
			kd_add(resp, "Session", "DEADBEEF");
			free(transport);
		} else {
			success = false;
			LOG_INFO("[%p]: cannot start session, missing ports", ctx);
		}

	} else if (strcmp(method, "RECORD") == 0) {
		unsigned short seqno = 0;
		unsigned rtptime = 0;
		char *p;

		if (atoi(ctx->latencies)) {
			char latency[6];
			snprintf(latency, 6, "%u", (atoi(ctx->latencies) * 44100) / 1000);
			kd_add(resp, "Audio-Latency", latency);
		}

		if ((buf = kd_lookup(headers, "RTP-Info")) != NULL) {
			if ((p = strcasestr(buf, "seq")) != NULL) sscanf(p, "%*[^=]=%hu", &seqno);
			if ((p = strcasestr(buf, "rtptime")) != NULL) sscanf(p, "%*[^=]=%u", &rtptime);
		}

		if (ctx->ht) raopst_record(ctx->ht, seqno, rtptime);
		ctx->raop_cb(ctx->owner, RAOP_STREAM, (uint32_t) ctx->hport);

	}  else if (!strcmp(method, "FLUSH")) {
		unsigned short seqno = 0;
		unsigned rtptime = 0;
		char *p;

		if ((buf = kd_lookup(headers, "RTP-Info")) != NULL) {
			if ((p = strcasestr(buf, "seq")) != NULL) sscanf(p, "%*[^=]=%hu", &seqno);
			if ((p = strcasestr(buf, "rtptime")) != NULL) sscanf(p, "%*[^=]=%u", &rtptime);
        }

		// only send FLUSH if useful (discards frames above buffer head and top)
		if (ctx->ht && raopst_flush(ctx->ht, seqno, rtptime, true, !ctx->flush)) {
			ctx->raop_cb(ctx->owner, RAOP_FLUSH);
			raopst_flush_release(ctx->ht);
		}

		// flag that we have received a flush and artwork might be outdated
		ctx->flushedArtwork = true;
	}  else if (!strcmp(method, "TEARDOWN")) {

		ctx->raop_cb(ctx->owner, RAOP_STOP);
		raopsr_metadata_free(&ctx->metadata);
		raopst_end(ctx->ht);

		ctx->ht = NULL;
		ctx->hport = -1;

		// need to make sure no search is on-going and reclaim pthread memory
		if (ctx->active_remote.handle) mdnssd_close(ctx->active_remote.handle);
		pthread_join(ctx->search_thread, NULL);
		memset(&ctx->active_remote, 0, sizeof(ctx->active_remote));

		NFREE(ctx->rtsp.aeskey);
		NFREE(ctx->rtsp.aesiv);
		NFREE(ctx->rtsp.fmtp);

	} else if (!strcmp(method, "SET_PARAMETER")) {
		char *p;

		if (body && (p = strcasestr(body, "volume")) != NULL) {
			double volume;

			sscanf(p, "%*[^:]:%lf", &volume);
			LOG_INFO("[%p]: SET PARAMETER volume %lf", ctx, volume);
			volume = (volume == -144.0) ? 0 : (1 + volume / 30);
			ctx->raop_cb(ctx->owner, RAOP_VOLUME, volume);
		} else if (((p = kd_lookup(headers, "Content-Type")) != NULL) && !strcasecmp(p, "application/x-dmap-tagged")) {
			dmap_settings settings = {
				NULL, NULL, NULL, NULL,	NULL, NULL,	NULL, on_dmap_string, NULL,
				NULL
			};

			// if artwork has been received after flush, keep it
			char* artwork = (!ctx->flushedArtwork && ctx->metadata.artwork) ? strdup(ctx->metadata.artwork) : NULL;
			raopsr_metadata_free(&ctx->metadata);
			ctx->metadata.artwork = artwork;
			settings.ctx = &ctx->metadata;

			if (!dmap_parse(&settings, body, len)) {
				ctx->raop_cb(ctx->owner, RAOP_METADATA, &ctx->metadata);
				raopst_metadata(ctx->ht, &ctx->metadata);
				LOG_INFO("[%p]: received metadata\n\tartist: %s\n\talbum:  %s\n\ttitle:  %s",
					ctx, ctx->metadata.artist,ctx->metadata.album, ctx->metadata.title);
			}
		} else if (body && ((p = kd_lookup(headers, "Content-Type")) != NULL) && strcasestr(p, "image/jpeg")) {
				static uint32_t count;
				char buffer[16];
				sprintf(buffer, "/%x.jpg", (ctx->metadata.title ? hash32(ctx->metadata.title) : 0) + count++);
				NFREE(ctx->metadata.artwork);
				ctx->metadata.artwork = http_pico_add_source(buffer, "image/jpeg", (uint8_t*) body, len, 120);
				LOG_INFO("[%p]: received JPEG image of %d bytes", ctx, len);
				ctx->flushedArtwork = false;
				ctx->raop_cb(ctx->owner, RAOP_ARTWORK, &ctx->metadata, body, len);
				raopst_metadata(ctx->ht, &ctx->metadata);
		}
	} else {
		success = false;
    	LOG_ERROR("[%p]: unknown/unhandled method %s", ctx, method);
	}

	// don't need to free "buf" because kd_lookup return a pointer, not a strdup

	kd_add(resp, "Audio-Jack-Status", "connected; type=analog");
	kd_add(resp, "CSeq", kd_lookup(headers, "CSeq"));

	if (success) buf = http_send(sock, "RTSP/1.0 200 OK", resp);
	else buf = http_send(sock, "RTSP/1.0 500 ERROR", NULL);

	if (strcmp(method, "OPTIONS")) {
		LOG_INFO("[%p]: responding:\n%s", ctx, buf ? buf : "<void>");
	}

	NFREE(body);
	NFREE(buf);
	kd_free(resp);
	kd_free(headers);

	return true;
}

/*----------------------------------------------------------------------------*/
static void event_cb(void *owner, raopst_event_t event) {
	raopsr_t *ctx = (raopsr_t*) owner;

	switch(event) {
		case RAOP_STREAMER_PLAY:
			ctx->raop_cb(ctx->owner, RAOP_PLAY, (uint32_t) ctx->hport);
			// in case of play after FLUSH, usually no metadata is re-sent
			if (ctx->metadata.title) ctx->raop_cb(ctx->owner, RAOP_METADATA, &ctx->metadata);
			break;
		default:
			LOG_ERROR("[%p]: unknown hairtunes event", ctx, event);
			break;
	}
}

/*----------------------------------------------------------------------------*/
static void http_cb(void *owner, struct key_data_s *headers, struct key_data_s *response) {
	// just callback owner, don't do much
	raopsr_t *ctx = (raopsr_t*) owner;
	if (ctx->http_cb) ctx->http_cb(ctx->owner, headers, response);
}

/*----------------------------------------------------------------------------*/
bool search_remote_cb(mdnssd_service_t *slist, void *cookie, bool *stop) {
	mdnssd_service_t *s;
	raopsr_t *ctx = (raopsr_t*) cookie;

	// see if we have found an active remote for our ID
	for (s = slist; s; s = s->next) {
		if (strcasestr(s->name, ctx->active_remote.DACPid)) {
			ctx->active_remote.host = s->addr;
			ctx->active_remote.port = s->port;
			LOG_INFO("[%p]: found ActiveRemote for %s at %s:%u", ctx, ctx->active_remote.DACPid,
								inet_ntoa(ctx->active_remote.host), ctx->active_remote.port);
			*stop = true;
			break;
		}
	}

	// let caller clear list
	return false;
}

/*----------------------------------------------------------------------------*/
static void* search_remote(void *args) {
	raopsr_t *ctx = (raopsr_t*) args;

	mdnssd_query(ctx->active_remote.handle, "_dacp._tcp.local", false, 0, &search_remote_cb, (void*) ctx);
	return NULL;
}


/*----------------------------------------------------------------------------*/
static char *rsa_apply(unsigned char *input, int inlen, int *outlen, int mode) {
	unsigned char *out;
	RSA *rsa;
	static char super_secret_key[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt\n"
	"wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U\n"
	"wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf\n"
	"/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/\n"
	"UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW\n"
	"BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa\n"
	"LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5\n"
	"NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm\n"
	"lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz\n"
	"aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu\n"
	"a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM\n"
	"oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z\n"
	"oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+\n"
	"k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL\n"
	"AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA\n"
	"cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf\n"
	"54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov\n"
	"17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc\n"
	"1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI\n"
	"LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ\n"
	"2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKY=\n"
	"-----END RSA PRIVATE KEY-----";

	BIO *bmem = BIO_new_mem_buf(super_secret_key, -1);
	rsa = PEM_read_bio_RSAPrivateKey(bmem, NULL, NULL, NULL);
	BIO_free(bmem);

	out = malloc(RSA_size(rsa));
	switch (mode) {
		case RSA_MODE_AUTH:
			*outlen = RSA_private_encrypt(inlen, input, out, rsa,
										  RSA_PKCS1_PADDING);
			break;
		case RSA_MODE_KEY:
			*outlen = RSA_private_decrypt(inlen, input, out, rsa,
										  RSA_PKCS1_OAEP_PADDING);
			break;
	}

	RSA_free(rsa);

	return (char*) out;
}

/*----------------------------------------------------------------------------*/
static int  base64_pad(char *src, char **padded) {
	int n = strlen(src) + strlen(src) % 4;

	*padded = malloc(n + 1);
	memset(*padded, '=', n);
	memcpy(*padded, src, strlen(src));
	(*padded)[n] = '\0';

	return strlen(*padded);
}

static void on_dmap_string(void *ctx, const char *code, const char *name, const char *buf, size_t len) {
	raopsr_metadata_t *metadata = (raopsr_metadata_t *) ctx;

	// make sure we stay null-terminated
	if (!strcasecmp(code, "minm")) metadata->title = strndup(buf, len);
	else if (!strcasecmp(code, "asar")) metadata->artist = strndup(buf, len);
	else if (!strcasecmp(code, "asal")) metadata->album = strndup(buf, len);
}

