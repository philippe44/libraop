/*
 * RAOP : Client to control an AirPlay device, cli simple example
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 *
 */

#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "../crosstools/src/platform.h"
#include <assert.h>

#include <sys/stat.h>
#include <sys/types.h>

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

#include "../crosstools/src/cross_thread.h"
#include "raop_client.h"
#include "../crosstools/src/cross_net.h"
#include "../crosstools/src/cross_ssl.h"
#include "cross_util.h"
#include "cross_log.h"
#include "http_fetcher.h"
#include "pairing.h"

#define RAOP_SEC(ntp) ((uint32_t)((ntp) >> 32))
#define RAOP_FRAC(ntp) ((uint32_t)(ntp))
#define RAOP_SECNTP(ntp) RAOP_SEC(ntp), RAOP_FRAC(ntp)

bool startsWith(const char *pre, const char *str)
{
	size_t lenpre = strlen(pre),
		   lenstr = strlen(str);
	return lenstr < lenpre ? false : memcmp(pre, str, lenpre) == 0;
}

// locals
static bool glMainRunning = true;
static pthread_t glCmdPipeReaderThread;
char cmdPipeName[256];
int cmdPipeFd;
char cmdPipeBuf[512];
int latency = MS2TS(1000, 44100);
struct raopcl_s *raopcl;
enum
{
	STOPPED,
	PAUSED,
	PLAYING
} status;

// debug level from tools & other elements
log_level util_loglevel;
log_level raop_loglevel;
log_level main_log;

// our debug level
log_level *loglevel = &main_log;

// different combination of debug levels per channel
struct debug_s
{
	int main, raop, util;
} debug[] = {
	{lSILENCE, lSILENCE, lSILENCE},
	{lERROR, lERROR, lERROR},
	{lINFO, lERROR, lERROR},
	{lINFO, lINFO, lERROR},
	{lDEBUG, lERROR, lERROR},
	{lDEBUG, lINFO, lERROR},
	{lDEBUG, lDEBUG, lERROR},
	{lSDEBUG, lINFO, lERROR},
	{lSDEBUG, lDEBUG, lERROR},
	{lSDEBUG, lSDEBUG, lERROR},
};

/*----------------------------------------------------------------------------*/
static int print_usage(char *argv[])
{
	char *name = strrchr(argv[0], '\\');

	name = (name) ? name + 1 : argv[0];

	printf("usage: %s <options> <player_ip> <filename ('-' for stdin)>\n"
		   "\t[-ntp print current NTP and exit\n"
		   "\t[-check print check info and exit\n"
		   "\t[-port <port number>] (defaults to 5000)\n"
		   "\t[-volume <volume> (0-100)]\n"
		   "\t[-latency <latency> (frames]\n"
		   "\t[-wait <wait>]  (start after <wait> milliseconds)\n"
		   "\t[-ntpstart <start>] (start at NTP <start> + <wait>)\n"
		   "\t[-encrypt] audio payload encryption\n"
		   "\t[-dacp <dacp_id>] (DACP id)\n"
		   "\t[-activeremote <activeremote_id>] (Active Remote id)\n"
		   "\t[-alac] send ALAC compressed audio\n"

		   "\t[-et <value>] (et in mDNS: 4 for airport-express and used to detect MFi)\n"
		   "\t[-md <value>] (md in mDNS: metadata capabilties 0=text, 1=artwork, 2=progress)\n"
		   "\t[-am <value>] (am in mDNS: modelname)\n"
		   "\t[-pk <value>] (pk in mDNS: pairing key info)\n"
		   "\t[-pw <value>] (pw in mDNS: password info)\n"

		   "\t[-secret <secret>] (valid secret for AppleTV)\n"
		   "\t[-password <password>] (device password)\n"
		   "\t[-udn <UDN>] (UDN name in mdns, required for password)\n"

		   "\t[-if <ipaddress>] (IP of the interface to bind to)\n"
		   "\t[-cmdpipe <path>] (optional named pipe for metadata/commands)\n"

		   "\t[-pair] enter pairing mode for AppleTV\n"
		   "\t[-debug <debug level>] (0 = silent)\n",
		   name);
	return -1;
}

/*----------------------------------------------------------------------------*/
static void init_platform()
{
	netsock_init();
	cross_ssl_load();
}

/*----------------------------------------------------------------------------*/
static void close_platform()
{
	netsock_close();
	cross_ssl_free();
}

/*----------------------------------------------------------------------------*/
static void *CmdPipeReaderThread(void *args)
{
	// O_RDWR keeps the pipe open even when no writer is connected
	cmdPipeFd = open(cmdPipeName, O_RDWR | O_NONBLOCK);
	if (cmdPipeFd == -1)
	{
		LOG_ERROR("Failed to open command pipe: %s (errno=%d)", cmdPipeName, errno);
		return NULL;
	}
	LOG_INFO("Command pipe ready: %s", cmdPipeName);

	struct
	{
		char *title;
		char *artist;
		char *album;
		int duration;
		int progress;
	} metadata = {"", "", "", 0, 0};

	while (glMainRunning)
	{
		ssize_t bytes_read = read(cmdPipeFd, cmdPipeBuf, sizeof(cmdPipeBuf) - 1);

		if (bytes_read > 0)
		{
			cmdPipeBuf[bytes_read] = '\0';
			char *save_ptr1, *save_ptr2;
			char *line = strtok_r(cmdPipeBuf, "\n", &save_ptr1);
			while (line != NULL)
			{
				if (!glMainRunning)
					break;
				// extract key-value pair within line
				char *key = strtok_r(line, "=", &save_ptr2);
				if (strlen(key) == 0)
					continue;
				char *value = strtok_r(NULL, "", &save_ptr2);
				if (value == NULL)
					value = "";

				if (strcmp(key, "TITLE") == 0)
				{
					metadata.title = value ? value : "";
				}
				else if (strcmp(key, "ARTIST") == 0)
				{
					metadata.artist = value ? value : "";
				}
				else if (strcmp(key, "ALBUM") == 0)
				{
					metadata.album = value ? value : "";
				}
				else if (strcmp(key, "DURATION") == 0)
				{
					metadata.duration = atoi(value);
				}
				else if (strcmp(key, "PROGRESS") == 0)
				{
					metadata.progress = atoi(value);
					raopcl_set_progress_ms(raopcl, metadata.progress * 1000, metadata.duration * 1000);
				}
				else if (strcmp(key, "ARTWORK") == 0)
				{
					if (startsWith("http://", value))
					{
						LOG_DEBUG("Downloading artwork from URL: %s", value);
						char *contentType;
						char *content;
						int size = http_fetch(value, &contentType, &content);
						if (size > 0 && glMainRunning)
						{
							LOG_INFO("Sending artwork to player...");
							raopcl_set_artwork(raopcl, contentType, size, content);
							free(content);
						}
						else
						{
							LOG_WARN("Unable to download artwork", value);
						}
					}
					else if (access(value, F_OK) == 0)
					{
						// local file
						LOG_DEBUG("Setting artwork from file: %s", value);
						FILE *infile;
						char *buffer;
						long numbytes;
						infile = fopen(value, "r");
						fseek(infile, 0L, SEEK_END);
						numbytes = ftell(infile);
						fseek(infile, 0L, SEEK_SET);
						buffer = (char *)calloc(numbytes, sizeof(char));
						fread(buffer, sizeof(char), numbytes, infile);
						fclose(infile);
						raopcl_set_artwork(raopcl, "image/jpg", numbytes, buffer);
						free(buffer);
					}
					else
					{
						LOG_WARN("Unable to process artwork path: %s", value);
					}
				}
				else if (strcmp(key, "VOLUME") == 0)
				{
					LOG_INFO("Setting volume to: %s", value);
					raopcl_set_volume(raopcl, raopcl_float_volume(atoi(value)));
				}
				else if (strcmp(key, "ACTION") == 0 && strcmp(value, "PAUSE") == 0)
				{
					if (status == PLAYING)
					{
						raopcl_pause(raopcl);
						raopcl_flush(raopcl);
						status = PAUSED;
						LOG_INFO("Pause at : %u.%u", RAOP_SECNTP(raopcl_get_ntp(NULL)));
					}
					else
					{
						LOG_WARN("Pause requested but player is already paused");
					}
				}
				else if (strcmp(key, "ACTION") == 0 && strcmp(value, "PLAY") == 0)
				{
					uint64_t now = raopcl_get_ntp(NULL);
					uint64_t start_at = now + MS2NTP(200) - TS2NTP(latency, raopcl_sample_rate(raopcl));
					status = PLAYING;
					raopcl_start_at(raopcl, start_at);
					LOG_INFO("Re-started at : %u.%u", RAOP_SECNTP(start_at));
				}
				else if (strcmp(key, "ACTION") == 0 && strcmp(value, "STOP") == 0)
				{
					status = STOPPED;
					LOG_INFO("Stopped at : %u.%u", RAOP_SECNTP(raopcl_get_ntp(NULL)));
					raopcl_stop(raopcl);
					break;
				}
				else if (strcmp(key, "ACTION") == 0 && strcmp(value, "SENDMETA") == 0)
				{
					LOG_INFO("Sending metadata: %p", metadata);
					raopcl_set_daap(raopcl, 4, "minm", 's', metadata.title,
									"asar", 's', metadata.artist,
									"asal", 's', metadata.album,
									"astn", 'i', 1);
				}

					line = strtok_r(NULL, "\n", &save_ptr1);
			}
			memset(cmdPipeBuf, 0, sizeof(cmdPipeBuf));
		}
		else if (bytes_read < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				usleep(50 * 1000);
			}
			else
			{
				LOG_ERROR("Error reading from command pipe: %s", strerror(errno));
				usleep(250 * 1000);
			}
		}
		else
		{
			usleep(50 * 1000);
		}
	}
	return NULL;
}
/*																		  */
/*----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	char *glDACPid = "1A2B3D4EA1B2C3D4";
	char *activeRemote = "ap5918800d";
	char *fname = NULL;
	char *cmdpipe = NULL;
	int volume = 0, wait = 0;
	struct
	{
		struct hostent *hostent;
		char *hostname;
		int port;
		char *udn;
		struct in_addr addr;
	} player = {0};
	player.port = 5000;

	int infile;
	uint8_t *buf;
	int i, n = -1, level = 3;
	raop_crypto_t crypto = RAOP_CLEAR;
	uint64_t start = 0, start_at = 0, last = 0, frames = 0;
	bool alac = false, encryption = false, auth = false, pairing_mode = false;
	char *passwd = "", *secret = "", *md = "0,1,2", *et = "0,4", *am = "", *pk = "", *pw = "";
	char *iface = NULL;
	uint32_t glNetmask;
	char glInterface[16] = "?";
	static struct in_addr glHost;
	char *pair_secret = NULL;

	// parse arguments
	for (i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-pair"))
		{
			pairing_mode = true;
		}
		else if (!strcmp(argv[i], "-ntp"))
		{
			uint64_t t = raopcl_get_ntp(NULL);
			printf("%" PRIu64 "\n", t);
			exit(0);
		}
		else if (!strcmp(argv[i], "-check"))
		{
			printf("cliraop check\n");
			exit(0);
		}
		else if (!strcmp(argv[i], "-port"))
		{
			player.port = atoi(argv[++i]);
		}
		else if (!strcmp(argv[i], "-volume"))
		{
			volume = atoi(argv[++i]);
		}
		else if (!strcmp(argv[i], "-latency"))
		{
			latency = MS2TS(atoi(argv[++i]), 44100);
		}
		else if (!strcmp(argv[i], "-wait"))
		{
			wait = atoi(argv[++i]);
		}
		else if (!strcmp(argv[i], "-ntpstart"))
		{
			sscanf(argv[++i], "%" PRIu64, &start);
		}
		else if (!strcmp(argv[i], "-encrypt"))
		{
			encryption = true;
		}
		else if (!strcmp(argv[i], "-dacp"))
		{
			glDACPid = argv[++i];
		}
		else if (!strcmp(argv[i], "-activeremote"))
		{
			activeRemote = argv[++i];
		}
		else if (!strcmp(argv[i], "-alac"))
		{
			alac = true;
		}
		else if (!strcmp(argv[i], "-et"))
		{
			et = argv[++i];
		}
		else if (!strcmp(argv[i], "-md"))
		{
			md = argv[++i];
		}
		else if (!strcmp(argv[i], "-am"))
		{
			am = argv[++i];
		}
		else if (!strcmp(argv[i], "-pk"))
		{
			pk = argv[++i];
		}
		else if (!strcmp(argv[i], "-pw"))
		{
			pw = argv[++i];
		}
		else if (!strcmp(argv[i], "-if"))
		{
			strcpy(glInterface, argv[++i]);
		}
		else if (!strcmp(argv[i], "-cmdpipe"))
		{
			cmdpipe = argv[++i];
		}
		else if (!strcmp(argv[i], "-secret"))
		{
			secret = argv[++i];
		}
		else if (!strcmp(argv[i], "-udn"))
		{
			player.udn = argv[++i];
		}
		else if (!strcmp(argv[i], "-debug"))
		{
			level = atoi(argv[++i]);
			if (level >= sizeof(debug) / sizeof(struct debug_s))
			{
				level = sizeof(debug) / sizeof(struct debug_s) - 1;
			}
		}
		else if (!strcmp(argv[i], "-password"))
		{
			passwd = argv[++i];
		}
		else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
		{
			return print_usage(argv);
		}
		else if (!player.hostname)
		{
			player.hostname = argv[i];
		}
		else if (!fname)
		{
			fname = argv[i];
		}
	}

	util_loglevel = debug[level].util;
	raop_loglevel = debug[level].raop;
	main_log = debug[level].main;

	glHost = get_interface(!strchr(glInterface, '?') ? glInterface : NULL, &iface, &glNetmask);
	LOG_INFO("Binding to %s [%s] with mask 0x%08x", inet_ntoa(glHost), iface, ntohl(glNetmask));
	NFREE(iface);

	if (pairing_mode)
	{
		if (!player.hostname)
		{
			printf("Error: IP address is required for pairing.\n");
			printf("Usage: %s -pair [-port <port>] <player_ip>\n", argv[0]);
			printf("Example: %s -pair 192.168.1.69\n", argv[0]);
			printf("Example: %s -pair -port 7000 192.168.1.69\n", argv[0]);
			exit(1);
		}

		// Default port for pairing is 7000 if not specified
		if (player.port == 5000)
		{
			player.port = 7000;
		}

		// Initialize platform/SSL for pairing
		netsock_init();
		cross_ssl_load();

		if (AppleTVpairing(NULL, &pair_secret, player.hostname, player.port))
		{
			fprintf(stderr, "\nPairing successful!\nSecret: %s\n", pair_secret ? pair_secret : "(none)");
			fflush(stderr);
		}
		else
		{
			fprintf(stderr, "Pairing failed.\n");
			fflush(stderr);
		}
		exit(0);
	}

	if (!player.hostname)
		return print_usage(argv);
	if (!fname)
		return print_usage(argv);

	if (!strcmp(fname, "-"))
	{
		infile = fileno(stdin);
		LOG_INFO("Reading audio from stdin");
	}
	else
	{
		// Check if this is a FIFO/named pipe
		struct stat st;
		bool is_fifo = false;

		if (stat(fname, &st) == 0)
		{
			// File exists, check if it's a FIFO
			is_fifo = S_ISFIFO(st.st_mode);
			LOG_INFO("Using existing audio source: %s (%s)", fname, is_fifo ? "named pipe" : "file");
		}
		else
		{
			// File doesn't exist - try to create as FIFO
			if (mkfifo(fname, 0666) == 0)
			{
				is_fifo = true;
				LOG_INFO("Created audio named pipe: %s", fname);
			}
			else
			{
				// Not a FIFO and couldn't create - will try to open as regular file
				LOG_WARN("Could not create FIFO, trying as regular file: %s", fname);
			}
		}

		// Open with O_NONBLOCK for FIFOs to avoid blocking on open
		int flags = O_RDONLY;
		if (is_fifo)
			flags |= O_NONBLOCK;

		if ((infile = open(fname, flags)) == -1)
		{
			LOG_ERROR("cannot open file %s", fname);
			close_platform();
			exit(1);
		}

		// For FIFOs, set back to blocking mode after opening
		if (is_fifo)
		{
			int file_flags = fcntl(infile, F_GETFL);
			fcntl(infile, F_SETFL, file_flags & ~O_NONBLOCK);
			LOG_INFO("Audio pipe opened (now in blocking mode for reads)");
		}
	}

	// get player's address
	player.hostent = gethostbyname(player.hostname);
	if (!player.hostent)
	{
		LOG_ERROR("Cannot resolve name %s", player.hostname);
		exit(1);
	}
	memcpy(&player.addr.s_addr, player.hostent->h_addr_list[0], player.hostent->h_length);

	if (am && strcasestr(am, "appletv") && pk && *pk && !secret)
	{
		LOG_ERROR("AppleTV requires authentication (need to send secret field)");
		exit(1);
	}

	// Setup command pipe and start reader thread before connecting
	if (cmdpipe)
	{
		strncpy(cmdPipeName, cmdpipe, sizeof(cmdPipeName) - 1);
		cmdPipeName[sizeof(cmdPipeName) - 1] = '\0';
		struct stat st;
		if (stat(cmdPipeName, &st) != 0)
		{
			if (mkfifo(cmdPipeName, 0666) != 0)
			{
				LOG_ERROR("Failed to create command pipe: %s", cmdPipeName);
				exit(1);
			}
		}
		pthread_create(&glCmdPipeReaderThread, NULL, CmdPipeReaderThread, NULL);
	}

	// init platform, initializes stdin
	init_platform();

	if ((encryption || auth) && strchr(et, '1'))
		crypto = RAOP_RSA;
	else
		crypto = RAOP_CLEAR;

	// if airport express, force auth
	if (am && strcasestr(am, "airport"))
	{
		auth = true;
	}

	// handle device password
	char *password = NULL;
	if (*passwd && pw && !strcasecmp(pw, "true"))
	{
		char *encrypted;
		// add up to 2 trailing '=' and adjust size
		asprintf(&encrypted, "%s==", passwd);
		encrypted[strlen(passwd) + strlen(passwd) % 4] = '\0';
		password = malloc(strlen(encrypted));
		size_t len = base64_decode(encrypted, password);
		free(encrypted);
		// xor with UDN
		for (size_t i = 0; i < len; i++)
			password[i] ^= player.udn[i];
		password[len] = '\0';
	}

	// create the raop context
	if ((raopcl = raopcl_create(glHost, 0, 0, glDACPid, activeRemote, alac ? RAOP_ALAC : RAOP_ALAC_RAW, DEFAULT_FRAMES_PER_CHUNK,
								latency, crypto, auth, secret, password, et, md,
								44100, 16, 2,
								volume > 0 ? raopcl_float_volume(volume) : -144.0)) == NULL)
	{
		LOG_ERROR("Cannot init RAOP %p", raopcl);
		close_platform();
		exit(1);
	}

	// connect to player
	LOG_INFO("Connecting to player: %s (%s:%hu)", player.udn ? player.udn : player.hostname, inet_ntoa(player.addr), player.port);
	if (!raopcl_connect(raopcl, player.addr, player.port, volume > 0))
	{
		LOG_ERROR("Cannot connect to AirPlay device %s:%hu, check firewall & port", inet_ntoa(player.addr), player.port);
		goto exit;
	}

	latency = raopcl_latency(raopcl);

	LOG_INFO("connected to %s on port %d, player latency is %d ms", inet_ntoa(player.addr),
			 player.port, (int)TS2MS(latency, raopcl_sample_rate(raopcl)));

	if (start || wait)
	{
		uint64_t now = raopcl_get_ntp(NULL);

		start_at = (start ? start : now) + MS2NTP(wait) -
				   TS2NTP(latency, raopcl_sample_rate(raopcl));

		LOG_INFO("now %u.%u, audio starts at NTP %u.%u (in %u ms)", RAOP_SECNTP(now), RAOP_SECNTP(start_at),
				 (start_at + TS2NTP(latency, raopcl_sample_rate(raopcl)) > now) ? (uint32_t)NTP2MS(start_at - now + TS2NTP(latency, raopcl_sample_rate(raopcl))) : 0);

		raopcl_start_at(raopcl, start_at);
	}

	start = raopcl_get_ntp(NULL);
	status = PLAYING;

	buf = malloc(DEFAULT_FRAMES_PER_CHUNK * 4);
	uint32_t KeepAlive = 0;
	bool got_eof = false;

	// keep reading audio from stdin until exit/EOF
	while (status != STOPPED && (!got_eof || raopcl_is_playing(raopcl)))
	{
		uint64_t playtime, now;

		now = raopcl_get_ntp(NULL);

		// execute every second
		if (now - last > MS2NTP(1000))
		{
			last = now;
			uint32_t elapsed = TS2MS(frames - raopcl_latency(raopcl), raopcl_sample_rate(raopcl));
			if (frames && frames > raopcl_latency(raopcl))
			{
				LOG_INFO("elapsed milliseconds: %" PRIu64, elapsed);
			}

			// send keepalive when needed (to prevent stop playback on homepods)
			if (!(KeepAlive++ & 0x0f))
				raopcl_keepalive(raopcl);
		}

		// send chunk if needed
		if (status == PLAYING && raopcl_accept_frames(raopcl))
		{
			n = read(infile, buf, DEFAULT_FRAMES_PER_CHUNK * 4);

			if (n < 0)
			{
				// Error on read
				LOG_ERROR("Error reading from audio source");
				break;
			}
			else if (n == 0)
			{
				// EOF - writer closed the pipe or end of file
				if (!got_eof)
				{
					LOG_INFO("End of audio stream reached, draining buffer...");
					got_eof = true;
				}
				continue;
			}

			raopcl_send_chunk(raopcl, buf, n / 4, &playtime);
			frames += n / 4;
		}
		else
		{
			// prevent full cpu usage if we're waiting on data
			usleep(1000);
		}
	}
	LOG_INFO("end of stream reached");

	glMainRunning = false;
	free(buf);
	raopcl_disconnect(raopcl);
	if (cmdpipe)
	{
		pthread_join(glCmdPipeReaderThread, NULL);
	}
	goto exit;

exit:
	LOG_INFO("exiting...");
	if (cmdpipe)
	{
		close(cmdPipeFd);
		unlink(cmdPipeName);
	}
	raopcl_destroy(raopcl);
	close_platform();
	return 0;
}