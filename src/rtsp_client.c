/*****************************************************************************
 * rtsp_client.c: RTSP Client
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
#include <ctype.h>
#include "aexcl_lib.h"
#include "rtsp_client.h"

#if WIN
#define poll WSAPoll
#endif

#define MAX_NUM_KD 20
typedef struct rtspcl_s {
    int fd;
    char url[128];
    int cseq;
    key_data_t exthds[MAX_KD];
    char *session;
	const char *useragent;
	struct in_addr local_addr;
} rtspcl_t;

extern log_level 	raop_loglevel;
static log_level	*loglevel = &raop_loglevel;

//trim string
static char *trim(char *s);
static char *rtrim(char *s);
static char *ltrim(char *s);

static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds, key_data_t *kd, char* url);


/*----------------------------------------------------------------------------*/
int rtspcl_get_serv_sock(struct rtspcl_s *p)
{
	return p->fd;
}


/*----------------------------------------------------------------------------*/
struct rtspcl_s *rtspcl_create(char *useragent)
{
	rtspcl_t *rtspcld;

	rtspcld = malloc(sizeof(rtspcl_t));
	memset(rtspcld, 0, sizeof(rtspcl_t));
	rtspcld->useragent = useragent;
	rtspcld->fd = -1;
	return rtspcld;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_connected(struct rtspcl_s *p)
{
	if (p->fd == -1) return false;

	return rtspcl_is_sane(p);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_sane(struct rtspcl_s *p)
{
	int n;
	struct pollfd pfds;

	pfds.fd = p->fd;
	pfds.events = POLLOUT;

	if (p->fd == -1) return true;

	n = poll(&pfds, 1, 0);
	if (n == - 1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, __u16 destport, char *sid)
{
	__u16 myport=0;
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);

	if (!p) return false;

	p->session = NULL;
	if ((p->fd = open_tcp_socket(local, &myport)) == -1) return false;
	if (!get_tcp_connect_by_host(p->fd, host, destport)) return false;

	getsockname(p->fd, (struct sockaddr*)&name, &namelen);
	memcpy(&p->local_addr,&name.sin_addr, sizeof(struct in_addr));
	sprintf(p->url,"rtsp://%s/%s", inet_ntoa(name.sin_addr),sid);

	return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_disconnect(struct rtspcl_s *p)
{
	bool rc = true;

	if (!p) return false;

	if (p->fd != -1) {
		rc = exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL);
		close(p->fd);
	}

	p->fd = -1;

	return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_destroy(struct rtspcl_s *p)
{
	bool rc;

	if (!p) return false;

	rc = rtspcl_disconnect(p);

	if (p->session) free(p->session);
	free(p);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data)
{
	int i = 0;

	if (!p) return false;

	while (p->exthds[i].key && i < MAX_KD - 1) {
		if ((unsigned char) p->exthds[i].key[0] == 0xff) break;
		i++;
	}

	if (i == MAX_KD - 2) return false;

	if (p->exthds[i].key) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
	}
	else p->exthds[i + 1].key = NULL;

	p->exthds[i].key = strdup(key);
	p->exthds[i].data = strdup(data);

	return true;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key)
{
	int i = 0;

	if (!p) return false;

	if (!p->exthds) return false;

	while (p->exthds[i].key) {
		if (!strcmp(key, p->exthds[i].key)){
			p->exthds[i].key[0]=0xff;
			return true;
		}
		i++;
	}

	return false;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_remove_all_exthds(struct rtspcl_s *p)
{
	int i = 0;

	if (!p) return false;

	while (p->exthds && p->exthds[i].key) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
		i++;
	}
	memset(p->exthds, 0, sizeof(p->exthds));

	return true;
}


/*----------------------------------------------------------------------------*/
char* rtspcl_local_ip(struct rtspcl_s *p)
{
	static char buf[16];

	if (!p) return NULL;

	return strcpy(buf, inet_ntoa(p->local_addr));
}


/*----------------------------------------------------------------------------*/
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp)
{
	if(!p) return false;

	return exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 1, NULL, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *rkd)
{
	key_data_t hds[2];
	char *temp;

	if (!p) return false;

	port->audio.rport = 0;

	hds[0].key = "Transport";
	hds[0].data = _aprintf("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
							(unsigned) port->ctrl.lport, (unsigned) port->time.lport);
	if (!hds[0].data) return false;
	hds[1].key = NULL;

	if (!exec_request(p, "SETUP", NULL, NULL, 0, 1, hds, rkd, NULL)) return false;
	free(hds[0].data);

	if ((temp = kd_lookup(rkd, "Session")) != NULL) {
		p->session = strdup(trim(temp));
		LOG_DEBUG("[%p]: <------- : %s: session:%s",p , p->session);
		return true;
	}
	else {
		free_kd(rkd);
		LOG_ERROR("[%p]: no session in response", p);
		return false;
	}
}


/*----------------------------------------------------------------------------*/
bool rtspcl_record(struct rtspcl_s *p, __u16 start_seq, __u32 start_ts, key_data_t *rkd)
{
	bool rc;
	key_data_t hds[3];

	if (!p) return false;

	if (!p->session){
		LOG_ERROR("[%p]: no session in progress", p);
		return false;
	}

	hds[0].key 	= "Range";
	hds[0].data = "npt=0-";
	hds[1].key 	= "RTP-Info";
	hds[1].data = _aprintf("seq=%u;rtptime=%u", (unsigned) start_seq, (unsigned) start_ts);
	if (!hds[1].data) return false;
	hds[2].key	= NULL;

	rc = exec_request(p, "RECORD", NULL, NULL, 0, 1, hds, rkd, NULL);
	free(hds[1].data);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param)
{
	if (!p) return false;

	return exec_request(p, "SET_PARAMETER", "text/parameters", param, 0, 1, NULL, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_artwork(struct rtspcl_s *p, __u32 timestamp, char *content_type, int size, char *image)
{
	key_data_t hds[2];
	char rtptime[20];

	if (!p) return false;

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	return exec_request(p, "SET_PARAMETER", content_type, image, size, 2, hds, NULL, NULL);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_set_daap(struct rtspcl_s *p, __u32 timestamp, int count, va_list args)
{
	key_data_t hds[2];
	char rtptime[20];
	char *q, *str;
	bool rc;
	int i;

	if (!p) return false;

	str = q = malloc(1024);
	if (!str) return false;

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	// set mandatory headers first, the final size will be set at the end
	q = (char*) memcpy(q, "mlit", 4) + 8;
	q = (char*) memcpy(q, "mikd", 4) + 4;
	for (i = 0; i < 3; i++) *q++ = 0; *q++ = 1;
	*q++ = 2;

	while (count-- && (q-str) < 1024) {
		char *fmt, type;
		__u32 size;

		fmt = va_arg(args, char*);
		type = va_arg(args, int);
		q = (char*) memcpy(q, fmt, 4) + 4;

		switch(type) {
			case 's': {
				char *data;

				data = va_arg(args, char*);
				size = strlen(data);
				for (i = 0; i < 4; i++) *q++ = size >> (24-8*i);
				q = (char*) memcpy(q, data, size) + size;
				break;
			}
			case 'i': {
				int data;
				data = va_arg(args, int);
				*q++ = 0; *q++ = 2;
				*q++ = (data >> 8); *q++ = data;
				break;
			}
		}
	}

	// set "mlit" object size
	for (i = 0; i < 4; i++) *(str + 4 + i) = (q-str-8) >> (24-8*i);

	rc = exec_request(p, "SET_PARAMETER", "application/x-dmap-tagged", str, q-str, 2, hds, NULL, NULL);
	free(str);
	return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_options(struct rtspcl_s *p)
{
	if(!p) return false;

	return exec_request(p, "OPTIONS", NULL, NULL, 0, 1, NULL, NULL, "*");
}

/*----------------------------------------------------------------------------*/
bool rtspcl_auth_setup(struct rtspcl_s *p)
{
	/* //itunes second
	char data[] = {
	0x01, 0x80, 0xc3, 0xb3, 0xe8, 0xd6, 0x22, 0xd0, 0x50, 0xeb, 0xd8,
	0x17, 0x40, 0x11, 0xd8, 0x93, 0x00, 0x55, 0x65, 0xe7, 0x56, 0x43,
	0x76, 0xff, 0x41, 0x12, 0x84, 0x92, 0xac, 0xfb, 0xec, 0xd4, 0x1d }; */
	//itunes first
	char data[] = {
	0x01, 0xad, 0xb2, 0xa4, 0xc7, 0xd5, 0x5c, 0x97, 0x6c, 0x34, 0xf9,
	0x2e, 0x0e, 0x05, 0x48, 0x90, 0x3b, 0x3a, 0x2f, 0xc6, 0x72, 0x2b,
	0x88, 0x58, 0x08, 0x76, 0xd2, 0x9c, 0x61, 0x94, 0x18, 0x52, 0x50 };

	if (!p) return false;

	return exec_request(p, "POST", "application/octet-stream", data, 33, 1, NULL, NULL, "/auth-setup");
}


/*----------------------------------------------------------------------------*/
bool rtspcl_flush(struct rtspcl_s *p, __u16 seq_number, __u32 timestamp)
{
	bool rc;
	key_data_t hds[2];

	if(!p) return false;

	hds[0].key	= "RTP-Info";
	hds[0].data	= _aprintf("seq=%u;rtptime=%u", (unsigned) seq_number, (unsigned) timestamp);
	if (!hds[0].data) return false;
	hds[1].key	= NULL;

	rc = exec_request(p, "FLUSH", NULL, NULL, 0, 1, hds, NULL, NULL);
	free(hds[0].data);

	return rc;
}


/*----------------------------------------------------------------------------*/
bool rtspcl_teardown(struct rtspcl_s *p)
{
	if (!p) return false;

	return exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL);
}

/*
 * send RTSP request, and get responce if it's needed
 * if this gets a success, *kd is allocated or reallocated (if *kd is not NULL)
 */
static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds, key_data_t *rkd, char* url)
{
	char line[2048];
	char *req;
	char buf[128];
	const char delimiters[] = " ";
	char *token,*dp;
	int i,j, rval, len;
	int timeout = 10000; // msec unit

	if(!rtspcld || rtspcld->fd == -1) return false;

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

	for (i = 0; rtspcld->exthds && rtspcld->exthds[i].key; i++) {
		if ((unsigned char) rtspcld->exthds[i].key[0] == 0xff) continue;
		sprintf(buf,"%s: %s\r\n", rtspcld->exthds[i].key, rtspcld->exthds[i].data);
		strcat(req, buf);
	}

	if (rtspcld->session != NULL )    {
		sprintf(buf,"Session: %s\r\n",rtspcld->session);
		strcat(req, buf);
	}

	strcat(req,"\r\n");
	len = strlen(req);

	if (content_type && content) {
		len += (length ? length : strlen(content));
		//strncat(req, content, length ? length : strlen(content));
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

	if (read_line(rtspcld->fd, line, sizeof(line), timeout, 0) <= 0) {
		if (get_response == 1) {
			LOG_ERROR("[%p]: response : %s request failed", rtspcld, line);
			return false;
		}
		else return true;
	}

	token = strtok(line, delimiters);
	token = strtok(NULL, delimiters);
	if (token == NULL || strcmp(token, "200")) {
		if(get_response == 1) {
			LOG_ERROR("[%p]: <------ : request failed, error %s", rtspcld, line);
			return false;
		}
	}
	else {
		LOG_DEBUG("[%p]: <------ : %s: request ok", rtspcld, token);
	}

	i = 0;
	if (rkd) rkd[0].key = NULL;

	while (read_line(rtspcld->fd, line, sizeof(line), timeout, 0) > 0) {
		LOG_DEBUG("[%p]: <------ : %s", rtspcld, line);
		timeout = 1000; // once it started, it shouldn't take a long time

		if (!rkd) continue;

		if (i && line[0] == ' ') {
			for(j = 0; j < strlen(line); j++) if (line[j] != ' ') break;
			rkd[i].data = strdup(line + j);
			continue;
		}

		dp = strstr(line,":");

		if (!dp){
			LOG_ERROR("[%p]: Request failed, bad header", rtspcld);
			free_kd(rkd);
			return false;
		}

		*dp = 0;
		rkd[i].key = strdup(line);
		rkd[i].data = strdup(dp + 1);
		i++;
	}

	if (rkd) rkd[i].key = NULL;

	return true;
}


char *ltrim(char *s)
{
	while(isspace(*s)) s++;
	return s;
}

char *rtrim(char *s)
{
	char* back = s + strlen(s);
	while(isspace(*--back));
	*(back+1) = '\0';
	return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}


