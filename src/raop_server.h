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
#include "mdnssvc.h"

typedef struct raopsr_metadata_s {
	char* artist;
	char* title;
	char* album;
	char* artwork;
} raopsr_metadata_t;

typedef enum { RAOP_STREAM, RAOP_PLAY, RAOP_FLUSH, RAOP_PAUSE, RAOP_STOP, RAOP_VOLUME, RAOP_METADATA, RAOP_ARTWORK } raopsr_event_t ;
typedef void (*raopsr_cb_t)(void *owner, raopsr_event_t event, ...);
typedef void (*raop_http_cb_t)(void *owner, struct key_data_s *headers, struct key_data_s *response);

struct raopsr_s* raopsr_create(struct in_addr host, struct mdnsd *svr, char *name,
						  char *model, unsigned char mac[6], char *stream_codec, bool stream_metadata,
						  bool drift, bool flush, char *latencies, void *owner,
						  raopsr_cb_t raop_cb, raop_http_cb_t http_cb,
						  unsigned short port_base, unsigned short port_range,
						  int http_length);
void	raopsr_update(struct raopsr_s *ctx, char *name, char *model);
void  	raopsr_delete(struct raopsr_s *ctx);
void	raopsr_notify(struct raopsr_s *ctx, raopsr_event_t event, void *param);

void	raopsr_metadata_free(raopsr_metadata_t* data);
void	raopsr_metadata_copy(raopsr_metadata_t* dst, raopsr_metadata_t *src);
