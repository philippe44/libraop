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

#define PUBLIC_KEY_SIZE 32
#define SECRET_KEY_SIZE 32
#define PRIVATE_KEY_SIZE 64
#define SIGNATURE_SIZE	64

#define MAX_KD 64

typedef struct rtspcl_s {
    int fd;
    char url[128];
    int cseq;
    key_data_t exthds[MAX_KD];
	char *session;
	const char *useragent;
	struct in_addr local_addr;
	struct {
		char realm[16], nonce[256+1];
		char ha1[32+1];
	} digest;
} rtspcl_t;

extern log_level 	raop_loglevel;
static log_level	*loglevel = &raop_loglevel;

static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds,
			 key_data_t *kd, char **resp_content, int *resp_len,
			 char* url);

/*----------------------------------------------------------------------------*/
int rtspcl_get_serv_sock(struct rtspcl_s *p) {
	return p->fd;
}

/*----------------------------------------------------------------------------*/
struct rtspcl_s *rtspcl_create(char *useragent) {
	rtspcl_t* rtspcld = malloc(sizeof(rtspcl_t));
	memset(rtspcld, 0, sizeof(rtspcl_t));
	rtspcld->useragent = useragent;
	rtspcld->fd = -1;
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
	if ((p->fd = open_tcp_socket(local, NULL, true)) == -1) return false;
	if (!tcp_connect_by_host(p->fd, host, destport)) return false;

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);

	getsockname(p->fd, (struct sockaddr*)&name, &namelen);
	memcpy(&p->local_addr,&name.sin_addr, sizeof(struct in_addr));

	sprintf(p->url,"rtsp://%s/%s", inet_ntoa(host), sid);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_disconnect(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = true;

	if (p->fd != -1) {
		rc = exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
		closesocket(p->fd);
	}

	if (p->session) free(p->session);
	p->session = NULL;
	p->fd = -1;

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_destroy(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = rtspcl_disconnect(p);
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

	if (!exec_request(p, "SETUP", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL)) return false;
	free(hds[0].data);

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

	if (!p->session){
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
	uint8_t* rsp;
	int rsp_len;

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

/*
 * send RTSP request, and get responce if it's needed
 * if this gets a success, *kd is allocated or reallocated (if *kd is not NULL)
 */
static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds,
				key_data_t *rkd, char **resp_content, int *resp_len, char* url) {
	char line[2048] = "";
	char *req;
	char buf[128];
	const char delimiters[] = " ";
	char *token,*dp;
	int i, rval, len, clen;
	int timeout = 10000; // msec unit
	struct pollfd pfds;
	key_data_t lkd[MAX_KD], *pkd;

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

	rval = send(rtspcld->fd, req, len, 0);
	LOG_DEBUG( "[%p]: ----> : write %s", rtspcld, req );
	free(req);

	if (rval != len) {
	   LOG_ERROR( "[%p]: couldn't write request (%d!=%d)", rtspcld, rval, len );
	}

	if (!get_response) return true;

	if (http_read_line(rtspcld->fd, line, sizeof(line), timeout, true) <= 0) {
		LOG_ERROR("[%p]: response : %s request failed", rtspcld, line);
		if (get_response == 1) return false;
		else return true;
	}

	token = strtok(line, delimiters);
	token = strtok(NULL, delimiters);

	// ignore 501 when 
	if (token == NULL || strcmp(token, "200")) {
		if (strcmp(token, "501") || strcmp(cmd, "OPTIONS")) {
			LOG_ERROR("[%p]: <------ : request failed, error %s %s", rtspcld, line, (token ? token : ""));
		}
		if (get_response == 1) return false;
	} else {
		LOG_DEBUG("[%p]: <------ : %s: request ok", rtspcld, token);
	}

	i = 0;
	clen = 0;
	if (rkd) pkd = rkd;
	else pkd = lkd;
	pkd[0].key = NULL;

	while (http_read_line(rtspcld->fd, line, sizeof(line), timeout, true) > 0) {
		LOG_DEBUG("[%p]: <------ : %s", rtspcld, line);
		timeout = 1000; // once it started, it shouldn't take a long time

		if (i && line[0] == ' ') {
			size_t j;
			for(j = 0; j < strlen(line); j++) if (line[j] != ' ') break;
			pkd[i].data = strdup(line + j);
			continue;
		}

		dp = strstr(line,":");

		if (!dp){
			LOG_ERROR("[%p]: Request failed, bad header", rtspcld);
			kd_free(pkd);
			return false;
		}

		*dp = 0;
		pkd[i].key = strdup(line);
		pkd[i].data = strdup(dp + 1);

		if (!strcasecmp(pkd[i].key, "Content-Length")) clen = atol(pkd[i].data);

		i++;
		pkd[i].key = NULL;
	}

	if (clen) {
		char *data = malloc(clen);
		int size = 0;

		while (data && size < clen) {
			int bytes = recv(rtspcld->fd, data + size, clen - size, 0);
			if (bytes <= 0) break;
			size += bytes;
		}

		if (!data || size != clen) {
			LOG_ERROR("[%p]: content length receive error %p %d", rtspcld, data, size);
		}

		LOG_INFO("[%p]: Body data len %d", rtspcld, clen, data);
		if (*loglevel >= lDEBUG) logdump(data, clen);

		if (resp_content) {
			*resp_content = data;
			if (resp_len) *resp_len = clen;
		} else free(data);
	}

	pkd[i].key = NULL;
	if (!rkd) kd_free(pkd);

	return true;
}