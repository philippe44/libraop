/*
 *  RAOP: main server interface
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 * 
 */

#pragma once

#include "cross_util.h"
#include "tinysvcmdns.h"

typedef struct raopsv_metadata_s {
	char artist[256];
	char title[256];
	char album[256];
	char artwork[256];
} raopsv_metadata_t;

typedef enum { RAOP_STREAM, RAOP_PLAY, RAOP_FLUSH, RAOP_PAUSE, RAOP_STOP, RAOP_VOLUME } raopsr_event_t ;
typedef void (*raopsr_cb_t)(void *owner, raopsr_event_t event, void *param);
typedef void (*http_cb_t)(void *owner, struct key_data_s *headers, struct key_data_s *response);

struct raopsr_s* raopsr_create(struct in_addr host, struct mdnsd *svr, char *name,
						  char *model, unsigned char mac[6], char *codec, bool metadata,
						  bool drift, bool flush, char *latencies, void *owner,
						  raopsr_cb_t raop_cb, http_cb_t http_cb,
						  unsigned short port_base, unsigned short port_range,
						  int http_length);
void		  raopsr_update(struct raopsr_s *ctx, char *name, char *model);
void  		  raopsr_delete(struct raopsr_s *ctx);
void		  raopsr_notify(struct raopsr_s *ctx, raopsr_event_t event, void *param);
