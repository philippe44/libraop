/*
 * RAOP : Client to control an AirPlay device, RTSP part
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 * 
 */
 
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <openssl/rand.h>

#ifdef USE_CURVE25519
#include "ed25519_signature.h"
#else
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif

#include "platform.h"

#include "aes_ctr.h"
#include "cross_net.h"
#include "cross_util.h"
#include "cross_log.h"
#include "rtsp_client.h"
#include "plist_bin.h"
#include "hap/pair.h"

#define PUBLIC_KEY_SIZE 32
#define SECRET_KEY_SIZE 32
#define PRIVATE_KEY_SIZE 64
#define SIGNATURE_SIZE	64

#define MAX_KD 64

#define BPLIST_CONTENT_TYPE "application/x-apple-binary-plist"

typedef struct rtspcl_s {
    int fd;
    char url[128];
    int cseq;
    key_data_t exthds[MAX_KD];
	char *session;
	const char *useragent;
	struct in_addr local_addr, peer_addr;
	char sid[32];
	struct {
		char realm[16], nonce[256+1];
		char ha1[32+1];
	} digest;
	// requests can come from the control thread and the application at the same time
	pthread_mutex_t mutex;
	// AirPlay 2: once paired, everything on the control connection is encrypted
	bool ap2;
	struct pair_cipher_context *cipher;
	struct { uint8_t *buf; size_t len; } enc, rx;	// ciphertext not yet forming a block, plaintext not yet parsed
} rtspcl_t;

extern log_level 	raop_loglevel;
static log_level	*loglevel = &raop_loglevel;

static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds,
			 key_data_t *kd, char **resp_content, int *resp_len,
			 char* url);
static bool exec_request_unlocked(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds,
			 key_data_t *kd, char **resp_content, int *resp_len,
			 char* url);

/*----------------------------------------------------------------------------*/
/* transport: clear text, or HomeKit-style ChaCha20-Poly1305 blocks once the  */
/* AirPlay 2 pairing is done (responses are then decrypted before parsing)    */
/*----------------------------------------------------------------------------*/
static bool buf_append(uint8_t **buf, size_t *len, const uint8_t *data, size_t n) {
	uint8_t *tmp = realloc(*buf, *len + n + 1);
	if (!tmp) return false;
	memcpy(tmp + *len, data, n);
	*len += n;
	tmp[*len] = '\0';		// headers are text, keep them searchable
	*buf = tmp;
	return true;
}

static void rx_reset(rtspcl_t *p) {
	free(p->enc.buf);
	free(p->rx.buf);
	memset(&p->enc, 0, sizeof(p->enc));
	memset(&p->rx, 0, sizeof(p->rx));
}

/*
 * read from the socket and decrypt all complete blocks into the rx buffer,
 * false on timeout, disconnection or decryption error
 */
static bool rtsp_fill(rtspcl_t *p, int timeout) {
	struct pollfd pfd = { .fd = p->fd, .events = POLLIN };
	uint8_t raw[4096], *plain = NULL;
	size_t plain_len = 0;
	ssize_t used;
	int n;

	if (poll(&pfd, 1, timeout) <= 0) return false;
	if ((n = recv(p->fd, (char*) raw, sizeof(raw), 0)) <= 0) return false;
	if (!buf_append(&p->enc.buf, &p->enc.len, raw, n)) return false;
	if (p->enc.len < 2) return true;

	used = pair_decrypt(&plain, &plain_len, p->enc.buf, p->enc.len, p->cipher);
	if (used < 0) {
		LOG_ERROR("[%p]: control channel decryption failed (%s)", p, pair_cipher_errmsg(p->cipher));
		return false;
	}

	memmove(p->enc.buf, p->enc.buf + used, p->enc.len - used);
	p->enc.len -= used;
	buf_append(&p->rx.buf, &p->rx.len, plain, plain_len);
	free(plain);

	return true;
}

/*
 * same as http_parse_simple, but for the encrypted channel: wait for a whole
 * response (headers and body) in the rx buffer, then split it
 */
static bool rtsp_parse_simple(rtspcl_t *p, char **request, key_data_list_t *rkd_list, char **body, int *len, int timeout) {
	key_data_t *rkd = rkd_list->kd;
	uint32_t start = gettime_ms();
	char *end = NULL, *line, *next, *dp;
	size_t used;
	int i = 0, clen = 0, elapsed;

	if (!p->cipher) return http_parse_simple(p->fd, request, rkd_list, body, len, timeout);

	rkd[0].key = NULL;
	if (len) *len = 0;

	// headers end with an empty line, then come Content-Length bytes of body
	while (!end || p->rx.len < (size_t) (end + 4 - (char*) p->rx.buf) + clen) {
		elapsed = gettime_ms() - start;
		if (elapsed >= timeout || !rtsp_fill(p, timeout - elapsed)) return false;
		if (p->rx.buf && (end = strstr((char*) p->rx.buf, "\r\n\r\n")) != NULL &&
			(dp = strcasestr((char*) p->rx.buf, "\r\nContent-Length:")) != NULL && dp < end) clen = atoi(dp + 17);
	}

	// request line
	line = (char*) p->rx.buf;
	next = strstr(line, "\r\n");
	*next = '\0';
	if (request) *request = strdup(line);

	// headers
	for (line = next + 2; line < end; line = next + 2) {
		next = strstr(line, "\r\n");
		*next = '\0';
		if ((dp = strchr(line, ':')) == NULL) continue;
		*dp = '\0';
		if (rkd_list->count && i >= rkd_list->count - 1) continue;
		rkd[i].key = strdup(line);
		rkd[i].data = strdup(strltrim(dp + 1));
		rkd[++i].key = NULL;
	}

	if (body && clen) {
		*body = malloc(clen + 1);
		memcpy(*body, end + 4, clen);
		(*body)[clen] = '\0';
	}
	if (len) *len = clen;

	// consume the response, the next one might already have started
	used = end + 4 - (char*) p->rx.buf + clen;
	memmove(p->rx.buf, p->rx.buf + used, p->rx.len - used + 1);
	p->rx.len -= used;

	return true;
}

/*
 * same as send, but encrypted once the control channel is
 */
static int rtsp_send(rtspcl_t *p, const char *data, int len) {
	uint8_t *enc;
	size_t enc_len, sent = 0;

	if (!p->cipher) return send(p->fd, data, len, 0);

	if (pair_encrypt(&enc, &enc_len, (const uint8_t*) data, len, p->cipher) < 0) {
		LOG_ERROR("[%p]: control channel encryption failed (%s)", p, pair_cipher_errmsg(p->cipher));
		return -1;
	}

	while (sent < enc_len) {
		ssize_t n = send(p->fd, (char*) enc + sent, enc_len - sent, 0);
		if (n <= 0) break;
		sent += n;
	}

	free(enc);
	return sent == enc_len ? len : -1;
}

/*----------------------------------------------------------------------------*/
int rtspcl_get_serv_sock(struct rtspcl_s *p) {
	return p->fd;
}

/*----------------------------------------------------------------------------*/
struct rtspcl_s *rtspcl_create(char const *useragent) {
	rtspcl_t* rtspcld = malloc(sizeof(rtspcl_t));
	memset(rtspcld, 0, sizeof(rtspcl_t));
	rtspcld->useragent = useragent;
	rtspcld->fd = -1;
	pthread_mutex_init(&rtspcld->mutex, NULL);
	return rtspcld;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_is_connected(struct rtspcl_s *p) {
	if (p->fd == -1) return false;
	return rtspcl_is_sane(p);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_sane(struct rtspcl_s *p) {
	struct pollfd pfds;

	pfds.fd = p->fd;
	pfds.events = POLLIN;

	if (p->fd == -1) return true;

	int n = poll(&pfds, 1, 0);
	if (n == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, uint16_t destport, char *sid) {
	if (!p) return false;

	p->session = NULL;
	p->ap2 = false;
	rx_reset(p);
	if (p->cipher) {
		pair_cipher_free(p->cipher);
		p->cipher = NULL;
	}

	if ((p->fd = open_tcp_socket(local, NULL, true)) == -1) return false;
	if (!tcp_connect_by_host(p->fd, host, destport)) return false;

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);

	getsockname(p->fd, (struct sockaddr*)&name, &namelen);
	memcpy(&p->local_addr,&name.sin_addr, sizeof(struct in_addr));
	p->peer_addr = host;
	strncpy(p->sid, sid ? sid : "", sizeof(p->sid) - 1);

	sprintf(p->url,"rtsp://%s/%s", inet_ntoa(host), sid);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_disconnect(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = true;

	pthread_mutex_lock(&p->mutex);

	if (p->fd != -1) {
		if (p->ap2) {
			// AirPlay 2 wants a plist body, an empty dictionary tears down everything
			plb_t *root = plb_dict();
			size_t len;
			uint8_t *body = plb_encode(root, &len);
			plb_free(root);
			rc = exec_request_unlocked(p, "TEARDOWN", BPLIST_CONTENT_TYPE, (char*) body, len, 1, NULL, NULL, NULL, NULL, NULL);
			free(body);
		} else {
			rc = exec_request_unlocked(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
		}
		closesocket(p->fd);
	}

	if (p->session) free(p->session);
	p->session = NULL;
	p->fd = -1;

	if (p->cipher) {
		pair_cipher_free(p->cipher);
		p->cipher = NULL;
	}
	rx_reset(p);
	p->ap2 = false;

	pthread_mutex_unlock(&p->mutex);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_destroy(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = rtspcl_disconnect(p);
	pthread_mutex_destroy(&p->mutex);
	free(p);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data) {
	if (!p) return false;

	int i = 0;

	while (p->exthds[i].key && i < MAX_KD - 1) {
		if ((unsigned char) p->exthds[i].key[0] == 0xff) break;
		i++;
	}

	if (i == MAX_KD - 2) return false;

	if (p->exthds[i].key) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
	} else p->exthds[i + 1].key = NULL;

	p->exthds[i].key = strdup(key);
	p->exthds[i].data = strdup(data);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key) {
	if (!p) return false;

	for (int i = 0; p->exthds[i].key; i++) {
		if (!strcmp(key, p->exthds[i].key)){
			p->exthds[i].key[0]=0xff;
			return true;
		}
	}

	return false;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_remove_all_exthds(struct rtspcl_s *p) {
	if (!p) return false;

	for (int i = 0; p->exthds[i].key; i++) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
	}

	memset(p->exthds, 0, sizeof(p->exthds));

	return true;
}

/*----------------------------------------------------------------------------*/
char* rtspcl_local_ip(struct rtspcl_s *p) {
	if (!p) return NULL;

	static char buf[16];
	return strcpy(buf, inet_ntoa(p->local_addr));
}

/*----------------------------------------------------------------------------*/
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *passwd) {
	if(!p) return false;

	if (passwd && *passwd) {
		char* auth;
		key_data_t kd[MAX_KD] = { 0 };

		// execute an announce request and parse the output to get realm and nonce
		exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 2, NULL, kd, NULL, NULL, NULL);

		if ((auth = kd_lookup(kd, "WWW-Authenticate")) != NULL) {
			char * buf;

			if ((buf = strcasestr(auth, "realm")) != NULL) sscanf(buf, "realm%*[^\"]\"%16[^\"]", p->digest.realm);
			if ((buf = strcasestr(auth, "nonce")) != NULL) sscanf(buf, "nonce%*[^\"]\"%256[^\"]", p->digest.nonce);

			// so that we don't keep password in memory
			asprintf(&buf, "%s:%s:%s", !strcasecmp(p->digest.realm, "raop") ? "iTunes" : "AirPlay", p->digest.realm, passwd);

			uint8_t ha1_bin[16];
			MD5((uint8_t*) buf, strlen(buf), ha1_bin);
			free(buf); buf = (char*) p->digest.ha1;
			bytes2hex(ha1_bin, sizeof(ha1_bin), &buf);
		}

		kd_free(kd);
	}

	return exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *rkd) {
	key_data_t hds[2];
	char *temp;

	if (!p) return false;

	port->audio.rport = 0;

	hds[0].key = "Transport";
	(void)! asprintf(&hds[0].data, "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
							(unsigned) port->ctrl.lport, (unsigned) port->time.lport);
	if (!hds[0].data) return false;
	hds[1].key = NULL;

	bool res = exec_request(p, "SETUP", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL);
	free(hds[0].data);
	if (!res) return false;

	if ((temp = kd_lookup(rkd, "Session")) != NULL) {
		p->session = strdup(strtrim(temp));
		LOG_DEBUG("[%p]: <------ : session:%s", p, p->session);
		return true;
	}
	else {
		kd_free(rkd);
		LOG_ERROR("[%p]: no session in response", p);
		return false;
	}
}

/*----------------------------------------------------------------------------*/
bool rtspcl_record(struct rtspcl_s *p, uint16_t start_seq, uint32_t start_ts, key_data_t *rkd) {
	if (!p) return false;

	// AirPlay 2 devices do not necessarily send a session id
	if (!p->session && !p->ap2) {
		LOG_ERROR("[%p]: no session in progress", p);
		return false;
	}

	key_data_t hds[3];

	hds[0].key 	= "Range";
	hds[0].data = "npt=0-";
	hds[1].key 	= "RTP-Info";
	(void)! asprintf(&hds[1].data, "seq=%u;rtptime=%u", (unsigned) start_seq, (unsigned) start_ts);
	if (!hds[1].data) return false;
	hds[2].key	= NULL;

	bool rc = exec_request(p, "RECORD", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL);
	free(hds[1].data);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param) {
	if (!p) return false;
	return exec_request(p, "SET_PARAMETER", "text/parameters", param, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_artwork(struct rtspcl_s *p, uint32_t timestamp, char *content_type, int size, char *image) {
	if (!p) return false;

	key_data_t hds[2];
	char rtptime[20];

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	return exec_request(p, "SET_PARAMETER", content_type, image, size, 2, hds, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_daap(struct rtspcl_s *p, uint32_t timestamp, int count, va_list args) {
	if (!p) return false;

	key_data_t hds[2];
	char rtptime[20];
	char* q, * str;

	str = q = malloc(1024);
	if (!str) return false;

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	// set mandatory headers first, the final size will be set at the end
	q = (char*) memcpy(q, "mlit", 4) + 8;
	q = (char*) memcpy(q, "mikd", 4) + 4;
	for (int i = 0; i < 3; i++) { *q++ = 0; } *q++ = 1;
	*q++ = 2;

	while (count-- && (q-str) < 1024) {
		char *fmt, type;
		uint32_t size;

		fmt = va_arg(args, char*);
		type = (char) va_arg(args, int);
		q = (char*) memcpy(q, fmt, 4) + 4;

		switch(type) {
			case 's': {
				char *data;

				data = va_arg(args, char*);
				size = strlen(data);
				for (int i = 0; i < 4; i++) *q++ = size >> (24-8*i);
				q = (char*) memcpy(q, data, size) + size;
				break;
			}
			case 'i': {
				int data;
				data = va_arg(args, int);
				for (int i = 0; i < 3; i++) { *q++ = 0; } *q++ = 2;
				*q++ = (data >> 8); *q++ = data;
				break;
			}
		}
	}

	// set "mlit" object size
	for (int i = 0; i < 4; i++) *(str + 4 + i) = (q-str-8) >> (24-8*i);

	bool rc = exec_request(p, "SET_PARAMETER", "application/x-dmap-tagged", str, q-str, 2, hds, NULL, NULL, NULL, NULL);
	free(str);
	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd) {
	if (!p) return false;
	return exec_request(p, "OPTIONS", NULL, NULL, 0, 1, NULL, rkd, NULL, NULL, "*");
}

/*----------------------------------------------------------------------------*/
bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret_hex) {
	uint8_t auth_pub[PUBLIC_KEY_SIZE], auth_priv[PRIVATE_KEY_SIZE];
	uint8_t verify_pub[PUBLIC_KEY_SIZE], verify_secret[SECRET_KEY_SIZE];
	uint8_t atv_pub[PUBLIC_KEY_SIZE], *atv_data;
	uint8_t secret[SECRET_KEY_SIZE], shared_secret[SECRET_KEY_SIZE];
	uint8_t signed_keys[SIGNATURE_SIZE];
	uint8_t *buf, *content;
	SHA512_CTX digest;
	uint8_t aes_key[16], aes_iv[16];
	aes_ctr_context ctx;
	int atv_len, len;
	bool rc = true;

	if (!p) return false;
	buf = secret;
	hex2bytes(secret_hex, &buf);

	// retrieve authentication keys from secret
#ifdef USE_CURVE25519
	ed25519_CreateKeyPair(auth_pub, auth_priv, NULL, secret);
#else
	EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, SECRET_KEY_SIZE);
	size_t size = SECRET_KEY_SIZE;
	EVP_PKEY_get_raw_private_key(priv_key, auth_priv, &size);
	EVP_PKEY_get_raw_public_key(priv_key, auth_priv + SECRET_KEY_SIZE, &size);
	EVP_PKEY_get_raw_public_key(priv_key, auth_pub, &size);
	EVP_PKEY_free(priv_key);
#endif
	// create a verification public key
	RAND_bytes(verify_secret, SECRET_KEY_SIZE);
	VALGRIND_MAKE_MEM_DEFINED(verify_secret, SECRET_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CalculatePublicKey(verify_pub, verify_secret);
#else
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, verify_secret, SECRET_KEY_SIZE);
	size = PUBLIC_KEY_SIZE;
	EVP_PKEY_get_raw_public_key(priv_key, verify_pub, &size);
	EVP_PKEY_free(priv_key);
#endif

	// POST the auth_pub and verify_pub concataned
	buf = malloc(4 + PUBLIC_KEY_SIZE * 2);
	len = 0;
	memcpy(buf, "\x01\x00\x00\x00", 4); len += 4;
	memcpy(buf + len, verify_pub, PUBLIC_KEY_SIZE); len += PUBLIC_KEY_SIZE;
	memcpy(buf + len, auth_pub, PUBLIC_KEY_SIZE); len += PUBLIC_KEY_SIZE;

	if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, (char**) &content, &atv_len, "/pair-verify")) {
		LOG_ERROR("[%p]: AppleTV verify step 1 failed (pair again)", p);
		free(buf);
		return false;
	}

	// get atv_pub and atv_data then create shared secret
	memcpy(atv_pub, content, PUBLIC_KEY_SIZE);
	atv_data = malloc(atv_len - PUBLIC_KEY_SIZE);
	memcpy(atv_data, content + PUBLIC_KEY_SIZE, atv_len - PUBLIC_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CreateSharedKey(shared_secret, atv_pub, verify_secret);
#else	
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, verify_secret, SECRET_KEY_SIZE);
	EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, atv_pub, PUBLIC_KEY_SIZE);
	EVP_PKEY_CTX* evp_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
	EVP_PKEY_derive_init(evp_ctx);
	EVP_PKEY_derive_set_peer(evp_ctx, peer_key);
	size = SECRET_KEY_SIZE;
	EVP_PKEY_derive(evp_ctx, shared_secret, &size);
	EVP_PKEY_CTX_free(evp_ctx);
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(priv_key);
#endif
	free(content);

	// build AES-key & AES-iv from shared secret digest
	SHA512_Init(&digest);
	SHA512_Update(&digest, "Pair-Verify-AES-Key", strlen("Pair-Verify-AES-Key"));
	SHA512_Update(&digest, shared_secret, SECRET_KEY_SIZE);
	SHA512_Final(buf, &digest);
	memcpy(aes_key, buf, 16);

	SHA512_Init(&digest);
	SHA512_Update(&digest, "Pair-Verify-AES-IV", strlen("Pair-Verify-AES-IV"));
	SHA512_Update(&digest, shared_secret, SECRET_KEY_SIZE);
	SHA512_Final(buf, &digest);
	memcpy(aes_iv, buf, 16);

	// sign the verify_pub and atv_pub
	memcpy(buf, verify_pub, PUBLIC_KEY_SIZE);
	memcpy(buf + PUBLIC_KEY_SIZE, atv_pub, PUBLIC_KEY_SIZE);
#ifdef USE_CURVE25519
	ed25519_SignMessage(signed_keys, auth_priv, NULL, buf, PUBLIC_KEY_SIZE * 2);
#else
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, auth_priv, SECRET_KEY_SIZE);
	EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, priv_key);
	size = SIGNATURE_SIZE;
	EVP_DigestSign(md_ctx, signed_keys, &size, buf, SIGNATURE_SIZE);
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(priv_key);
#endif

	// encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
	aes_ctr_init(&ctx, aes_key, aes_iv, CTR_BIG_ENDIAN);
	memcpy(buf, atv_data, atv_len - PUBLIC_KEY_SIZE);
	aes_ctr_encrypt(&ctx, buf, atv_len - PUBLIC_KEY_SIZE);
	memcpy(buf + 4, signed_keys, SIGNATURE_SIZE);
	aes_ctr_encrypt(&ctx, buf + 4, SIGNATURE_SIZE);
	memcpy(buf, "\x00\x00\x00\x00", 4);
	len = SIGNATURE_SIZE + 4;
	free(atv_data);

	if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, NULL, NULL, "/pair-verify")) {
		LOG_ERROR("[%p]: AppleTV verify step 2 failed (pair again)", p);
		rc = false;
	}

	free(buf);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_auth_setup(struct rtspcl_s *p) {
	if (!p) return false;

	uint8_t secret[SECRET_KEY_SIZE], * pub_key = malloc(PUBLIC_KEY_SIZE + 1);
	uint8_t* rsp = NULL;  // Initialize to NULL - may not be set if no response body
	int rsp_len = 0;

	// create a verification public key
	RAND_bytes(secret, SECRET_KEY_SIZE);
	VALGRIND_MAKE_MEM_DEFINED(secret, SECRET_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CalculatePublicKey(pub_key + 1, secret);
#else
	EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);
	size_t size = PUBLIC_KEY_SIZE;
	EVP_PKEY_get_raw_public_key(key, pub_key + 1, &size);
	EVP_PKEY_free(key);
#endif
	// POST the auth_pub and verify_pub concataned
	pub_key[0] = '\x01';

	if (!exec_request(p, "POST", "application/octet-stream", (char*) pub_key,
					  PUBLIC_KEY_SIZE+1, 1, NULL, NULL, (char**) &rsp, &rsp_len, "/auth-setup")) {
		LOG_ERROR("[%p]: auth-setup failed", p);
		free(pub_key);
		return false;
	}

	free(pub_key);
	free(rsp);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_flush(struct rtspcl_s *p, uint16_t seq_number, uint32_t timestamp) {
	if(!p) return false;

	bool rc;
	key_data_t hds[2];

	hds[0].key	= "RTP-Info";
	(void)! asprintf(&hds[0].data, "seq=%u;rtptime=%u", (unsigned) seq_number, (unsigned) timestamp);
	if (!hds[0].data) return false;
	hds[1].key	= NULL;

	rc = exec_request(p, "FLUSH", NULL, NULL, 0, 1, hds, NULL, NULL, NULL, NULL);
	free(hds[0].data);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_teardown(struct rtspcl_s *p) {
	if (!p) return false;
	return exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
/* AirPlay 2                                                                  */
/*----------------------------------------------------------------------------*/
bool rtspcl_get_info(struct rtspcl_s *p, rtspcl_info_t *info) {
	char *body = NULL;
	int len = 0;
	int64_t v;
	const char *s;
	plb_t *root, *item;

	if (!p || !info) return false;
	memset(info, 0, sizeof(*info));

	if (!exec_request(p, "GET", NULL, NULL, 0, 1, NULL, NULL, &body, &len, "/info")) return false;

	if (!body || len <= 0) {
		free(body);
		return false;
	}

	root = plb_decode((uint8_t*) body, len);
	free(body);

	if (!root) {
		LOG_WARN("[%p]: cannot parse /info response", p);
		return false;
	}

	if ((item = plb_get(root, "features")) != NULL) {
		if (item->type == PLB_INT) info->features = (uint64_t) item->i;
		else if (item->type == PLB_STRING) {
			// same format than the mDNS TXT record "0x<low>,0x<high>"
			uint64_t low = 0, high = 0;
			if (sscanf(item->s, "%" SCNx64 ",%" SCNx64, &low, &high) >= 1) info->features = low | (high << 32);
		}
	}
	if (plb_get_int(root, "statusFlags", &v)) info->status_flags = (uint64_t) v;
	if ((s = plb_get_string(root, "model")) != NULL) strncpy(info->model, s, sizeof(info->model) - 1);
	if ((s = plb_get_string(root, "name")) != NULL) strncpy(info->name, s, sizeof(info->name) - 1);
	if ((s = plb_get_string(root, "sourceVersion")) != NULL) strncpy(info->source_version, s, sizeof(info->source_version) - 1);

	if (*loglevel >= lDEBUG) {
		char *dump = plb_dump(root);
		LOG_DEBUG("[%p]: /info %s", p, dump);
		free(dump);
	}

	plb_free(root);
	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_ap2_enable(struct rtspcl_s *p) {
	if (!p || p->fd == -1) return false;

	p->ap2 = true;
	// AirPlay 2 senders use their own address in the session url
	snprintf(p->url, sizeof(p->url), "rtsp://%s/%s", inet_ntoa(p->local_addr), p->sid);

	// senders identify themselves, use the product part of the user agent
	const char *ua = p->useragent ? p->useragent : "libraop";
	char name[64];
	snprintf(name, sizeof(name), "%.*s", (int) strcspn(ua, "/"), ua);
	rtspcl_add_exthds(p, "X-Apple-Client-Name", name);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_ap2_pair_transient(struct rtspcl_s *p, uint8_t *shared_secret, size_t *secret_len) {
	struct pair_setup_context *ctx = NULL;
	struct pair_result *result;
	key_data_t hds[2] = { { "X-Apple-HKP", "4" }, { NULL, NULL } };
	char device_id[17], *rsp = NULL;
	uint8_t *req;
	size_t req_len;
	int rsp_len = 0;
	bool rc = false;

	if (!p || p->fd == -1) return false;

	snprintf(device_id, sizeof(device_id), "%08X%08X", hash32(p->sid), hash32(p->url));

	pthread_mutex_lock(&p->mutex);

	if ((ctx = pair_setup_new(PAIR_CLIENT_HOMEKIT_TRANSIENT, NULL, NULL, NULL, device_id)) == NULL) {
		LOG_ERROR("[%p]: cannot create pairing context", p);
		goto exit;
	}

	// M1 -> M2 (salt and SRP public key of the device)
	if ((req = pair_setup_request1(&req_len, ctx)) == NULL) {
		LOG_ERROR("[%p]: pair-setup M1 error: %s", p, pair_setup_errmsg(ctx));
		goto exit;
	}
	rc = exec_request_unlocked(p, "POST", "application/octet-stream", (char*) req, req_len, 1, hds, NULL, &rsp, &rsp_len, "/pair-setup");
	free(req);
	if (!rc || !rsp) {
		LOG_ERROR("[%p]: pair-setup step 1 failed", p);
		rc = false;
		goto exit;
	}
	if (pair_setup_response1(ctx, (uint8_t*) rsp, rsp_len) < 0) {
		LOG_ERROR("[%p]: pair-setup M2 error: %s", p, pair_setup_errmsg(ctx));
		rc = false;
		goto exit;
	}
	free(rsp);
	rsp = NULL;

	// M3 -> M4 (SRP proofs)
	if ((req = pair_setup_request2(&req_len, ctx)) == NULL) {
		LOG_ERROR("[%p]: pair-setup M3 error: %s", p, pair_setup_errmsg(ctx));
		rc = false;
		goto exit;
	}
	rc = exec_request_unlocked(p, "POST", "application/octet-stream", (char*) req, req_len, 1, hds, NULL, &rsp, &rsp_len, "/pair-setup");
	free(req);
	if (!rc || !rsp) {
		LOG_ERROR("[%p]: pair-setup step 2 failed", p);
		rc = false;
		goto exit;
	}
	if (pair_setup_response2(ctx, (uint8_t*) rsp, rsp_len) < 0) {
		LOG_ERROR("[%p]: pair-setup M4 error: %s", p, pair_setup_errmsg(ctx));
		rc = false;
		goto exit;
	}

	if (pair_setup_result(NULL, &result, ctx) < 0) {
		LOG_ERROR("[%p]: transient pairing not completed: %s", p, pair_setup_errmsg(ctx));
		rc = false;
		goto exit;
	}

	if (result->shared_secret_len > *secret_len) {
		LOG_ERROR("[%p]: shared secret too large (%zu > %zu)", p, result->shared_secret_len, *secret_len);
		rc = false;
		goto exit;
	}
	memcpy(shared_secret, result->shared_secret, result->shared_secret_len);
	*secret_len = result->shared_secret_len;

	// from now on, everything on this connection is encrypted
	rx_reset(p);
	p->cipher = pair_cipher_new(PAIR_CLIENT_HOMEKIT_TRANSIENT, PAIR_CHANNEL_CONTROL, result->shared_secret, result->shared_secret_len, NULL);
	if (!p->cipher) {
		LOG_ERROR("[%p]: cannot create control channel cipher", p);
		rc = false;
		goto exit;
	}

	LOG_INFO("[%p]: AirPlay 2 transient pairing done, control channel is now encrypted", p);
	rc = true;

exit:
	free(rsp);
	if (ctx) pair_setup_free(ctx);
	pthread_mutex_unlock(&p->mutex);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_ap2_setup_session(struct rtspcl_s *p, uint16_t timing_lport, uint16_t *event_port, uint16_t *timing_rport) {
	uint8_t rnd[16], *body;
	char device_id[18], uuid[37], *rsp = NULL, *s;
	key_data_t kd[MAX_KD] = { { NULL, NULL } };
	plb_t *root;
	size_t len;
	int rsp_len = 0;
	int64_t v;
	bool rc;

	if (!p || p->fd == -1 || !event_port) return false;

	*event_port = 0;
	if (timing_rport) *timing_rport = 0;

	RAND_bytes(rnd, sizeof(rnd));
	VALGRIND_MAKE_MEM_DEFINED(rnd, sizeof(rnd));
	snprintf(device_id, sizeof(device_id), "%02X:%02X:%02X:%02X:%02X:%02X", rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]);
	snprintf(uuid, sizeof(uuid), "%02X%02X%02X%02X-%02X%02X-4%01X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			 rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6] & 0x0f, rnd[7],
			 (rnd[8] & 0x3f) | 0x80, rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);

	root = plb_dict();
	plb_dict_set(root, "deviceID", plb_string(device_id));
	plb_dict_set(root, "sessionUUID", plb_string(uuid));
	plb_dict_set(root, "timingPort", plb_int(timing_lport));
	plb_dict_set(root, "timingProtocol", plb_string("NTP"));
	body = plb_encode(root, &len);
	plb_free(root);

	rc = exec_request(p, "SETUP", BPLIST_CONTENT_TYPE, (char*) body, len, 1, NULL, kd, &rsp, &rsp_len, NULL);
	free(body);
	if (!rc) return false;

	if ((s = kd_lookup(kd, "Session")) != NULL) {
		if (p->session) free(p->session);
		p->session = strdup(strtrim(s));
	}
	kd_free(kd);

	if (rsp && rsp_len > 0 && (root = plb_decode((uint8_t*) rsp, rsp_len)) != NULL) {
		if (plb_get_int(root, "eventPort", &v)) *event_port = (uint16_t) v;
		if (timing_rport && plb_get_int(root, "timingPort", &v)) *timing_rport = (uint16_t) v;
		if (*loglevel >= lDEBUG) {
			char *dump = plb_dump(root);
			LOG_DEBUG("[%p]: SETUP (session) response %s", p, dump);
			free(dump);
		}
		plb_free(root);
	} else {
		LOG_WARN("[%p]: no usable plist in SETUP (session) response", p);
	}
	free(rsp);

	LOG_INFO("[%p]: AirPlay 2 session established (event port %hu)", p, *event_port);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_ap2_setup_stream(struct rtspcl_s *p, uint16_t ctrl_lport, const uint8_t *shk, size_t shk_len,
							 uint32_t stream_id, bool alac, int sample_rate, int frames_per_packet,
							 uint32_t latency_min, uint32_t latency_max, uint16_t *data_port, uint16_t *ctrl_port) {
	plb_t *root, *streams, *stream;
	uint8_t *body;
	char *rsp = NULL;
	size_t len;
	int rsp_len = 0;
	int64_t v;
	bool rc;

	if (!p || p->fd == -1 || !data_port || !ctrl_port) return false;

	*data_port = *ctrl_port = 0;

	stream = plb_dict();
	// see https://openairplay.github.io/airplay-spec/audio/formats.html
	if (alac) plb_dict_set(stream, "audioFormat", plb_int(sample_rate == 48000 ? 0x100000 : 0x40000));
	else plb_dict_set(stream, "audioFormat", plb_int(sample_rate == 48000 ? 0x8000 : 0x800));
	plb_dict_set(stream, "audioMode", plb_string("default"));
	plb_dict_set(stream, "controlPort", plb_int(ctrl_lport));
	plb_dict_set(stream, "ct", plb_int(alac ? 2 : 1));
	plb_dict_set(stream, "isMedia", plb_bool(true));
	plb_dict_set(stream, "latencyMax", plb_int(latency_max));
	plb_dict_set(stream, "latencyMin", plb_int(latency_min));
	plb_dict_set(stream, "shk", plb_data(shk, shk_len));
	plb_dict_set(stream, "spf", plb_int(frames_per_packet));
	plb_dict_set(stream, "sr", plb_int(sample_rate));
	plb_dict_set(stream, "type", plb_int(0x60));
	plb_dict_set(stream, "supportsDynamicStreamID", plb_bool(false));
	plb_dict_set(stream, "streamConnectionID", plb_int(stream_id));

	streams = plb_array();
	plb_array_add(streams, stream);
	root = plb_dict();
	plb_dict_set(root, "streams", streams);
	body = plb_encode(root, &len);
	plb_free(root);

	rc = exec_request(p, "SETUP", BPLIST_CONTENT_TYPE, (char*) body, len, 1, NULL, NULL, &rsp, &rsp_len, NULL);
	free(body);
	if (!rc) return false;

	if (rsp && rsp_len > 0 && (root = plb_decode((uint8_t*) rsp, rsp_len)) != NULL) {
		if (*loglevel >= lDEBUG) {
			char *dump = plb_dump(root);
			LOG_DEBUG("[%p]: SETUP (stream) response %s", p, dump);
			free(dump);
		}
		stream = plb_at(plb_get(root, "streams"), 0);
		if (stream) {
			if (plb_get_int(stream, "dataPort", &v)) *data_port = (uint16_t) v;
			if (plb_get_int(stream, "controlPort", &v)) *ctrl_port = (uint16_t) v;
		}
		plb_free(root);
	}
	free(rsp);

	if (!*data_port || !*ctrl_port) {
		LOG_ERROR("[%p]: missing port in SETUP (stream) response (data %hu, control %hu)", p, *data_port, *ctrl_port);
		return false;
	}

	LOG_INFO("[%p]: AirPlay 2 stream negotiated (data port %hu, control port %hu)", p, *data_port, *ctrl_port);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_ap2_feedback(struct rtspcl_s *p) {
	if (!p || p->fd == -1) return false;
	return exec_request(p, "POST", NULL, NULL, 0, 2, NULL, NULL, NULL, NULL, "/feedback");
}

/*----------------------------------------------------------------------------*/
static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds,
				key_data_t *rkd, char **resp_content, int *resp_len, char* url) {
	if (!rtspcld) return false;

	pthread_mutex_lock(&rtspcld->mutex);
	bool rc = exec_request_unlocked(rtspcld, cmd, content_type, content, length, get_response, hds, rkd, resp_content, resp_len, url);
	pthread_mutex_unlock(&rtspcld->mutex);

	return rc;
}

/*
 * send RTSP request, and get responce if it's needed
 * if this gets a success, *kd is allocated or reallocated (if *kd is not NULL)
 * get_response: 0 = don't wait, 1 = must be 200, 2 = read response but accept any status
 */
static bool exec_request_unlocked(rtspcl_t *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds,
				key_data_t *rkd, char **resp_content, int *resp_len, char* url) {
	char *req;
	char buf[128];
	int i, len, rval;
	struct pollfd pfds;

	if (!rtspcld || rtspcld->fd == -1) return false;

	pfds.fd = rtspcld->fd;
	pfds.events = POLLOUT;

	i = poll(&pfds, 1, 0);
	if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	if ((req = malloc(4096+length)) == NULL) return false;

	sprintf(req, "%s %s RTSP/1.0\r\n",cmd, url ? url : rtspcld->url);

	for (i = 0; hds && hds[i].key != NULL; i++) {
		sprintf(buf, "%s: %s\r\n", hds[i].key, hds[i].data);
		strcat(req, buf);
	}

	if (content_type && content) {
		sprintf(buf, "Content-Type: %s\r\nContent-Length: %d\r\n", content_type, length ? length : (int) strlen(content));
		strcat(req, buf);
	}

	sprintf(buf,"CSeq: %d\r\n", ++rtspcld->cseq);
	strcat(req, buf);

	sprintf(buf, "User-Agent: %s\r\n", rtspcld->useragent );
	strcat(req, buf);

	for (i = 0; rtspcld->exthds[i].key; i++) {
		if ((unsigned char) rtspcld->exthds[i].key[0] == 0xff) continue;
		sprintf(buf,"%s: %s\r\n", rtspcld->exthds[i].key, rtspcld->exthds[i].data);
		strcat(req, buf);
	}

	if (rtspcld->session != NULL )    {
		sprintf(buf,"Session: %s\r\n",rtspcld->session);
		strcat(req, buf);
	}

	// add digest if we have a password
	if (*rtspcld->digest.ha1) {
		char* buf, digest[32+1];
		asprintf(&buf, "%s:%s", cmd, url ? url : rtspcld->url);
		unsigned char ha2_bin[16], ha2[32+1];
		MD5((uint8_t*) buf, strlen(buf), ha2_bin);

		free(buf); buf = (char*) ha2;
		bytes2hex(ha2_bin, sizeof(ha2_bin), &buf);
		asprintf(&buf, "%s:%s:%s", rtspcld->digest.ha1, rtspcld->digest.nonce, ha2);
		unsigned char digest_bin[16];
		MD5((uint8_t*) buf, strlen(buf), digest_bin);

		free(buf); buf = digest;
		bytes2hex(digest_bin, sizeof(digest_bin), &buf);

		sprintf(req + strlen(req), "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n", 
			!strcasecmp(rtspcld->digest.realm, "raop") ? "iTunes" : "AirPlay", rtspcld->digest.realm,
			rtspcld->digest.nonce, url ? url : rtspcld->url, digest);
	}

	strcat(req,"\r\n");
	len = strlen(req);

	if (content_type && content) {
		len += (length ? length : strlen(content));
		memcpy(req + strlen(req), content, length ? length : strlen(content));
		req[len] = '\0';
	}

	rval = rtsp_send(rtspcld, req, len);
	LOG_DEBUG( "[%p]: ----> : write %s", rtspcld, req );
	free(req);

	if (rval != len) {
	   LOG_ERROR( "[%p]: couldn't write request (%d!=%d)", rtspcld, rval, len );
	}

	if (!get_response) return true;

	const char delimiters[] = " ";
	char *token, *body = NULL, *request = NULL;
	int clen = 0;
	bool result = true;
	key_data_list_t headers = { 
		.count = rkd ? 0 : MAX_KD, 
		.kd = rkd ? rkd : (key_data_t[MAX_KD]) { { 0 } } 
	};

	if (rtsp_parse_simple(rtspcld, &request, &headers, &body, &clen, 10000) <= 0) {
		LOG_ERROR("[%p]: response : %s request failed", rtspcld, request ? request : "");
		if (get_response == 1) result = false;
		goto cleanup;
	}

	token = strtok(request, delimiters);
	token = strtok(NULL, delimiters);

	// ignore 501 when used with OPTIONS
	if (token == NULL || strcmp(token, "200")) {
		if (token == NULL || strcmp(token, "501") || strcmp(cmd, "OPTIONS")) {
			LOG_ERROR("[%p]: <------ : request failed, error %s %s", rtspcld, request ? request : "", token ? token : "");
		}
		if (get_response == 1) {
			result = false;
			goto cleanup;
		}
	} else {
		LOG_DEBUG("[%p]: <------ : %s: request ok", rtspcld, token);
	}

	// free various items that callers might not want
cleanup:
	if (result && resp_content) {
		*resp_content = body;
		if (resp_len) *resp_len = clen;
	} else if (body) {
		free(body);
	}
	
	if (!result || !rkd) kd_free(headers.kd);

	if (request) free(request);

	return result;
}
