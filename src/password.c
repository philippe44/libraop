/*
 *  Squeeze2raop - Squeezelite to AirPlay bridge
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 *  See LICENSE
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "cross_log.h"
#include "cross_util.h"
#include "cross_net.h"
#include "mdnssd.h"

static uint32_t netmask;
static cross_queue_t players;

/*----------------------------------------------------------------------------*/
static bool searchCallback(mdnssd_service_t* slist, void* excluded, bool* stop) {
	for (mdnssd_service_t* s = slist; s; s = s->next) {
		if (!s->name || (s->host.s_addr != s->addr.s_addr && ((s->host.s_addr & netmask) == (s->addr.s_addr & netmask)))) continue;

		char* am = NULL;
		for (int i = 0; i < s->attr_count; i++)	if (!strcasecmp(s->attr[i].name, "am")) am = s->attr[i].value;
		if (!am || (excluded && !strstr(excluded, am))) queue_insert(&players, strdup(s->name));
	}
	return false;
}

bool AirPlayPassword(struct mdnssd_handle_s* mDNShandle, char* excluded, char **UDN, char **passwd) {
	struct mdnssd_handle_s* mDNS = mDNShandle;

	// create a queue for player's name (UDN)
	queue_init(&players, false, free);

	if (!mDNS) {
		struct in_addr host = get_interface(NULL, NULL, &netmask);
		mDNS = mdnssd_init(false, host, true);
		if (!mDNS) return false;
	}

	printf("please wait 5 seconds...\n");
	mdnssd_query(mDNS, "_raop._tcp.local", false, 5, &searchCallback, excluded);
	
	// list devices
	int idx = 1;
	printf("\npick a player to set password\n\n");
	for (char* player = queue_walk_start(&players); player; player = queue_walk_next(&players)) {
		char name[128+1];
		sscanf(player, "%*[^@]@%128[^.]", name);
		printf("%d - %s\n", idx++, name);
	}
	queue_walk_end(&players);

	printf("\nenter an index (0 to exit): ");
	(void)!scanf("%d", &idx);
	if (!idx) return false;

	printf("enter password (can be empty): ");
	*passwd = calloc(32 + 1, 1);
	// good old scanf on stdin...
	(void)!scanf("%*c%32[^\n]", *passwd);

	char* player = queue_walk_start(&players);
	while (--idx) player = queue_walk_next(&players);
	queue_walk_end(&players);
	*UDN = strdup(player);
	
	if (!mDNShandle) mdnssd_close(mDNS);
	return true;
}
