/*
 *  Squeeze2raop - LMS to Raop gateway
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __PLATFORM_H
#define __PLATFORM_H

#if defined(linux)
#define LINUX     1
#define OSX       0
#define WIN       0
#define FREEBSD   0
#elif defined (__APPLE__)
#define LINUX     0
#define OSX       1
#define WIN       0
#define FREEBSD   0
#elif defined (_MSC_VER) || defined(__BORLANDC__)
#define LINUX     0
#define OSX       0
#define WIN       1
#define FREEBSD   0
#elif defined(__FreeBSD__)
#define LINUX     0
#define OSX       0
#define WIN       0
#define FREEBSD   1
#else
#error unknown target
#endif

#include <stdbool.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>

#if LINUX || OSX || FREEBSD
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/poll.h>
#include <poll.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <memcheck.h>

#define last_error() errno
#define ERROR_WOULDBLOCK EWOULDBLOCK

int SendARP(in_addr_t src, in_addr_t dst, u8_t mac[], u32_t *size);
#define fresize(f,s) ftruncate(fileno(f), s)
char *strlwr(char *str);
#define _random(x) random()
char *GetTempPath(u16_t size, char *path);
#define closesocket close

#endif

#if WIN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>

#define usleep(x) Sleep((x)/1000)
#define sleep(x) Sleep((x)*1000)

#define ERROR_WOULDBLOCK WSAEWOULDBLOCK
#define open _open
#define read _read
#define fresize(f, s) chsize(fileno(f), s)
#define strcasecmp stricmp
#define random rand

int poll(struct pollfd* fds, unsigned long numfds, int timeout);
int asprintf(char** s, const char* fmt, ...);
int vasprintf(char** strp, const char* fmt, va_list args);

#define VALGRIND_MAKE_MEM_DEFINED(x,y)

typedef uint32_t in_addr_t;
#define socklen_t int
typedef SSIZE_T	ssize_t;

#define RTLD_NOW 0

#endif

uint32_t gettime_ms(void);
uint64_t gettime_ms64(void);

#endif     // __PLATFORM
