/*****************************************************************************
 * rtsp_play.c: RAOP Client player
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
#include <signal.h>
#include <fcntl.h>
#include "platform.h"

#if WIN
#include <conio.h>
#include <time.h>
#else
#include <unistd.h>
#include <termios.h>
#include <sys/param.h>
#include <sys/time.h>
#if OSX || FREEBDS
#include <sys/resource.h>
#endif
#endif

#include "aexcl_lib.h"
#include "raop_client.h"
#include "alac_wrapper.h"

#define SEC(ntp) ((__u32) ((ntp) >> 32))
#define FRAC(ntp) ((__u32) (ntp))
#define SECNTP(ntp) SEC(ntp),FRAC(ntp)

log_level	util_loglevel;
log_level	raop_loglevel;
log_level 	main_log;

log_level *loglevel =&main_log;

struct debug_s {
	int main, raop, util;
} debug[] = { { lSILENCE, lSILENCE, lSILENCE },
			{ lERROR, lERROR, lERROR },
			{ lINFO, lERROR, lERROR },
			{ lINFO, lINFO, lERROR },
			{ lDEBUG, lERROR, lERROR },
			{ lDEBUG, lINFO, lERROR },
			{ lDEBUG, lDEBUG, lERROR },
			{ lSDEBUG, lINFO, lERROR },
			{ lSDEBUG, lDEBUG, lERROR },
			{ lSDEBUG, lSDEBUG, lERROR },
		};

/*----------------------------------------------------------------------------*/
static int print_usage(char *argv[])
{
	char *name = strrchr(argv[0], '\\');

	name = (name) ? name + 1 :argv[0];

	printf("usage: %s <options> <server_ip> <filename ('-' for stdin)>\n"
			   "\t[-ntp <file>] write current NTP in <file> and exit\n"
			   "\t[-p <port number>]\n"
			   "\t[-v <volume> (0-100)]\n"
			   "\t[-l <latency> (frames]\n"
			   "\t[-w <wait>]  (start after <wait> milliseconds)\n"
			   "\t[-n <start>] (start at NTP <start> + <wait>)\n"
			   "\t[-nf <start>] (start at NTP in <file> + <wait>)\n"
			   "\t[-e] (encrypt)\n"
   			   "\t[-a] send ALAC compressed audio\n"
			   "\t[-s <secret>] (valid secret for AppleTV)\n"
			   "\t[-t <et>] (et field in mDNS - used to detect MFi)\n"
			   "\t[-m <[0][,1][,2]>] (md in mDNS: metadata capabilties 0=text, 1=artwork, 2=progress)\n"
			   "\t[-d <debug level>] (0 = silent)\n"
			   "\t[-i] (interactive commands: 'p'=pause, 'r'=(re)start, 's'=stop, 'q'=exit, ' '=block)\n",
			   name);
	return -1;
}


#if WIN
struct timezone
{
	int  tz_minuteswest; /* minutes W of Greenwich */
	int  tz_dsttime;     /* type of dst correction */
};

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
	#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
	#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

/*----------------------------------------------------------------------------*/
static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (tv) {
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/*converting file time to unix epoch*/
		tmpres /= 10;  /*convert into microseconds*/
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	if (tz) {
		if (!tzflag) {
			_tzset();
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}

#else // WIN

/*----------------------------------------------------------------------------*/
static int kbhit()
{
	struct timeval tv;

	fd_set fds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
	select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
	return FD_ISSET(STDIN_FILENO, &fds);
}

/*----------------------------------------------------------------------------*/
static void set_termio(bool canon) {
	struct termios ios = {0};

	tcgetattr(0, &ios);

	if (canon) {
		ios.c_lflag |= ICANON;
		ios.c_lflag |= ECHO;
		tcsetattr(0, TCSADRAIN, &ios);
	}
	else {
		ios.c_lflag &= ~ICANON;
		ios.c_lflag &= ~ECHO;
		ios.c_cc[VMIN] = 1;
		ios.c_cc[VTIME] = 0;
		tcsetattr(0, TCSANOW, &ios);
	}
}

/*----------------------------------------------------------------------------*/
static char _getch() {
	char buf;

	if (read(0, &buf, 1)) return buf;

	return '\0';
}

#endif


/*----------------------------------------------------------------------------*/
static void init_platform(bool interactive) {
#if WIN
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int WSerr = WSAStartup(wVersionRequested, &wsaData);
	if (WSerr != 0) exit(1);
#else
	if (interactive) set_termio(false);
#endif
}

/*----------------------------------------------------------------------------*/
static void close_platform(bool interactive) {
#if WIN
	WSACleanup();
#else
	if (interactive) set_termio(true);
#endif
}

/*----------------------------------------------------------------------------*/
u64_t get_ntp(struct ntp_s *ntp)
{
	struct timeval ctv;
	struct ntp_s local;

	gettimeofday(&ctv, NULL);
	local.seconds  = ctv.tv_sec + 0x83AA7E80;
	local.fraction = (((__u64) ctv.tv_usec) << 32) / 1000000;

	if (ntp) *ntp = local;

	return (((__u64) local.seconds) << 32) + local.fraction;
}


/*----------------------------------------------------------------------------*/
/*																			  */
/*----------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {
	struct raopcl_s *raopcl;
	char *fname = NULL;
	int port = 5000;
	int volume = 50, wait = 0, latency = MS2TS(1000, 44100);
	struct {
		struct hostent *hostent;
		char *name;
		struct in_addr addr;
	} player = { NULL, NULL, { INADDR_ANY } };
	int infile;
	u8_t *buf;
	int i, n = -1, level = 2;
	enum {STOPPED, PAUSED, PLAYING } status;
	raop_crypto_t crypto = RAOP_CLEAR;
	__u64 start = 0, start_at = 0, last = 0, frames = 0;
	bool interactive = false, alac = false;
	char *secret = NULL, *md = NULL, *et = NULL;
	struct in_addr host = { INADDR_ANY };

	for(i = 1; i < argc; i++){
		if(!strcmp(argv[i],"-ntp")){
			FILE *out;

			out = fopen(argv[2], "w");
			fprintf(out, "%llu", get_ntp(NULL));
			fclose(out);
			exit(0);
		}

		if(!strcmp(argv[i],"-p")){
			port=atoi(argv[++i]);
			continue;
		}
		if(!strcmp(argv[i],"-v")){
			volume=atoi(argv[++i]);
			continue;
		}
		if(!strcmp(argv[i],"-w")){
			wait=atoi(argv[++i]);
			continue;
		}
		if(!strcmp(argv[i],"-l")){
			latency=atoi(argv[++i]);
			continue;
		}
		if(!strcmp(argv[i],"-i")){
			interactive = true;
			continue;
		}
		if(!strcmp(argv[i],"-s")){
			secret = argv[++i];
			continue;
		}
		if(!strcmp(argv[i],"-m")){
			md = argv[++i];
			continue;
		}
		if(!strcmp(argv[i],"-t")){
			et = argv[++i];
			continue;
		}
		if(!strcmp(argv[i],"-a")){
			alac = true;
			continue;
		}
		if(!strcmp(argv[i],"-n")){
			sscanf(argv[++i], "%llu", &start);
			continue;
		}
		if(!strcmp(argv[i],"-nf")){
			FILE *in;

			in = fopen(argv[++i], "r");
			if (!in || !fscanf(in, "%llu", &start)) {
				LOG_ERROR("Cannot read NTP from file %s", argv[i]);
			}
			fclose(in);
			continue;
		}
		if(!strcmp(argv[i],"-d")){
			level = atoi(argv[++i]);
			if (level >= sizeof(debug) / sizeof(struct debug_s)) {
				level = sizeof(debug) / sizeof(struct debug_s) - 1;
			}
			continue;
		}
		if(!strcmp(argv[i],"-e")){
			crypto = RAOP_RSA;
			continue;
		}
		if(!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h"))
			return print_usage(argv);
		if (!player.name) {player.name = argv[i]; continue;}
		if (!fname) {fname=argv[i]; continue;}
	}

	if (!player.name) return print_usage(argv);
	if (!fname) return print_usage(argv);

	util_loglevel = debug[level].util;
	raop_loglevel = debug[level].raop;
	main_log = debug[level].main;

	if (!strcmp(fname, "-")) {
		infile = fileno(stdin);
		interactive = false;
	}
	else {
		if ((infile = open(fname, O_RDONLY)) == -1) {
			LOG_ERROR("cannot open file %s", fname);
			close_platform(interactive);
			exit(1);
		}
	}

#if WIN
	setmode(infile, O_BINARY);
#endif

	init_platform(interactive);

	if ((raopcl = raopcl_create(host, 0, 0, NULL, NULL, alac ? RAOP_ALAC : RAOP_PCM, MAX_SAMPLES_PER_CHUNK,
								latency, crypto, false, secret, et, md,
								44100, 16, 2,
								raopcl_float_volume(volume))) == NULL) {
		LOG_ERROR("Cannot init RAOP %p", raopcl);
		close_platform(interactive);
		exit(1);
	}

	player.hostent = gethostbyname(player.name);
	memcpy(&player.addr.s_addr, player.hostent->h_addr_list[0], player.hostent->h_length);

	if (!raopcl_connect(raopcl, player.addr, port, true)) {
		raopcl_destroy(raopcl);
		free(raopcl);
		LOG_ERROR("Cannot connect to AirPlay device %s, check firewall",
				   inet_ntoa(player.addr));
		close_platform(interactive);
		exit(1);
	}

	latency = raopcl_latency(raopcl);

	LOG_INFO("connected to %s on port %d, player latency is %d ms", inet_ntoa(player.addr),
			 port, (int) TS2MS(latency, raopcl_sample_rate(raopcl)));

	if (start || wait) {
		__u64 now = get_ntp(NULL);

		start_at = (start ? start : now) + MS2NTP(wait) -
					TS2NTP(latency, raopcl_sample_rate(raopcl));

		LOG_INFO("now %u.%u, audio starts at NTP %u.%u (in %u ms)", SECNTP(now), SECNTP(start_at),
				 (start_at + TS2NTP(latency, raopcl_sample_rate(raopcl)) > now) ?
				  (__u32) NTP2MS(start_at - now + TS2NTP(latency, raopcl_sample_rate(raopcl))) :
				  0);

		raopcl_start_at(raopcl, start_at);
	}

	start = get_ntp(NULL);
	status = PLAYING;

	buf = malloc(MAX_SAMPLES_PER_CHUNK*4);

	do {
		__u64 playtime, now;

		now = get_ntp(NULL);

		if (now - last > MS2NTP(1000)) {
			last = now;
			if (frames && frames > raopcl_latency(raopcl)) {
				LOG_INFO("at %u.%u (%Lu ms after start), played %Lu ms",
						  SECNTP(now), NTP2MS(now - start),
						  TS2MS(frames - raopcl_latency(raopcl), raopcl_sample_rate(raopcl)));
			}
		}

		if (status == PLAYING && raopcl_accept_frames(raopcl)) {
			n = read(infile, buf, MAX_SAMPLES_PER_CHUNK*4);
			if (!n)	continue;
			raopcl_send_chunk(raopcl, buf, n / 4, &playtime);
			frames += n / 4;
		}

		if (interactive && kbhit()) {
			char c = _getch();

			switch (c) {
			case 'p':
				if (status == PLAYING) {
					raopcl_pause(raopcl);
					raopcl_flush(raopcl);
					status = PAUSED;
					LOG_INFO("Pause at : %u.%u", SECNTP(get_ntp(NULL)));
				}
				break;
			case 's':
				raopcl_stop(raopcl);
				raopcl_flush(raopcl);
				status = STOPPED;
				LOG_INFO("Stopped at : %u.%u", SECNTP(get_ntp(NULL)));
				break;
			case 'r': {
				__u64 now = get_ntp(NULL);
				__u64 start_at = now + MS2NTP(200) - TS2NTP(latency, raopcl_sample_rate(raopcl));

				status = PLAYING;
				raopcl_start_at(raopcl, start_at);
				LOG_INFO("Re-started at : %u.%u", SECNTP(start_at));
				}
				break;
			case 'q':
				raopcl_disconnect(raopcl);
				raopcl_destroy(raopcl);
				free(buf);
				close_platform(interactive);
				exit(0);
			case ' ':
				_getch();
				break;
			default: break;
			}
		}

	} while (n || raopcl_is_playing(raopcl));

	raopcl_disconnect(raopcl);
	raopcl_destroy(raopcl);
	free(buf);

	close_platform(interactive);

	return 0;
}
