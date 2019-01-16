#include <stdio.h>

#include "platform.h"

#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "log_util.h"

#ifndef __AEXCL_LIB_H_
#define __AEXCL_LIB_H_

#define MAX_KD 64

#define GET_BIGENDIAN_INT(x) (*(u8_t*)(x)<<24)|(*((u8_t*)(x)+1)<<16)|(*((u8_t*)(x)+2)<<8)|(*((u8_t*)(x)+3))


typedef struct {
	char *key;
	char *data;
} key_data_t;


typedef struct sock_info_s {
	int fd;
	u16_t lport;
	u16_t rport;
} sock_info_t;


typedef struct rtp_port_s {
	sock_info_t time;
	sock_info_t	ctrl;
	sock_info_t audio;
} rtp_port_t;

int open_tcp_socket(struct in_addr host, unsigned short *port);
int open_udp_socket(struct in_addr host, unsigned short *port, bool blocking);
bool get_tcp_connect_by_host(int sd, struct in_addr host, unsigned short destport);
bool get_tcp_connect(int sd, struct sockaddr_in dest_addr);
bool bind_host(int sd, struct in_addr host,unsigned short *port);
int read_line(int fd, char *line, int maxlen, int timeout, int no_poll);
char *kd_lookup(key_data_t *kd, char *key);
void free_kd(key_data_t *kd);
int remove_char_from_string(char *str, char rc);
char *_aprintf(const char *fmt, ...);
#if WIN
int poll(struct pollfd *fds, unsigned long numfds, int timeout);
#endif
int hex2bytes(char *hex, u8_t **bytes);


#endif
