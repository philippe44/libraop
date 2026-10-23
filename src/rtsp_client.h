/*
 * RAOP : Client to control an AirPlay device, RTSP part
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 *
 */

 #ifndef __RTSP_CLIENT_H
#define __RTSP_CLIENT_H

typedef struct sock_info_s {
	int fd;
	uint16_t lport;
	uint16_t rport;
} sock_info_t;

typedef struct rtp_port_s {
	sock_info_t time;
	sock_info_t	ctrl;
	sock_info_t audio;
} rtp_port_t;

// what a device tells about itself in GET /info (AirPlay 2 capable devices)
typedef struct rtspcl_info_s {
	uint64_t features;
	uint64_t status_flags;
	char model[64];
	char name[64];
	char source_version[32];
} rtspcl_info_t;

#define RTSP_FEATURE_HK_PAIRING			(1ULL << 46)
#define RTSP_FEATURE_TRANSIENT_PAIRING	(1ULL << 48)
#define RTSP_STATUS_PIN_REQUIRED		(1ULL << 3)
#define RTSP_STATUS_PASSWORD_REQUIRED	(1ULL << 7)
#define RTSP_STATUS_ONE_TIME_PAIRING	(1ULL << 9)

struct rtspcl_s *rtspcl_create(char const *user_name);
bool   			rtspcl_destroy(struct rtspcl_s *p);

bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, unsigned short destport, char *sid);
bool rtspcl_disconnect(struct rtspcl_s *p);
bool rtspcl_is_connected(struct rtspcl_s *p);
bool rtspcl_is_sane(struct rtspcl_s *p);
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);
bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret);
bool rtspcl_auth_setup(struct rtspcl_s *p);
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *passwd);
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *kd);
bool rtspcl_record(struct rtspcl_s *p, uint16_t start_seq, uint32_t start_ts, key_data_t *kd);
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param);
bool rtspcl_flush(struct rtspcl_s *p, uint16_t seq_number, uint32_t timestamp);
bool rtspcl_set_daap(struct rtspcl_s *p, uint32_t timestamp, int count, va_list args);
bool rtspcl_set_artwork(struct rtspcl_s *p, uint32_t timestamp, char *content_type, int size, char *image);

bool rtspcl_remove_all_exthds(struct rtspcl_s *p);
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data);
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key);
char* rtspcl_local_ip(struct rtspcl_s *p);

/*
 AirPlay 2: HomeKit transient pairing, encrypted control channel and plist
 based SETUP. Sequence is get_info (optional) -> ap2_enable -> ap2_pair_transient
 -> ap2_setup_session -> ap2_setup_stream -> record, then feedback periodically.
 For ap2_pair_transient, *secret_len is the size of shared_secret on input and
 the length of the secret (needed for the event channel cipher) on output
*/
bool rtspcl_get_info(struct rtspcl_s *p, rtspcl_info_t *info);
bool rtspcl_ap2_enable(struct rtspcl_s *p);
bool rtspcl_ap2_pair_transient(struct rtspcl_s *p, uint8_t *shared_secret, size_t *secret_len);
bool rtspcl_ap2_setup_session(struct rtspcl_s *p, uint16_t timing_lport, uint16_t *event_port, uint16_t *timing_rport);
bool rtspcl_ap2_setup_stream(struct rtspcl_s *p, uint16_t ctrl_lport, const uint8_t *shk, size_t shk_len,
							 uint32_t stream_id, bool alac, int sample_rate, int frames_per_packet,
							 uint32_t latency_min, uint32_t latency_max, uint16_t *data_port, uint16_t *ctrl_port);
bool rtspcl_ap2_feedback(struct rtspcl_s *p);

#endif
