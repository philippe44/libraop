/*
 *  plist_bin - small binary plist (bplist00) reader & writer with nesting,
 *  enough for the AirPlay 2 SETUP/info exchanges
 *
 *  See LICENSE
 *
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum { PLB_NULL, PLB_BOOL, PLB_INT, PLB_REAL, PLB_STRING, PLB_DATA, PLB_ARRAY, PLB_DICT } plb_type_t;

typedef struct plb_s {
	plb_type_t type;
	char *key;					// set when the node is a dictionary member
	struct plb_s *next;			// next sibling in the parent container
	struct plb_s *children;		// members of an array or dictionary
	int count;
	bool b;
	int64_t i;
	double r;
	char *s;
	uint8_t *data;
	size_t len;
} plb_t;

// builders (containers take ownership of the values they receive)
plb_t *plb_dict(void);
plb_t *plb_array(void);
plb_t *plb_string(const char *s);
plb_t *plb_int(int64_t v);
plb_t *plb_bool(bool v);
plb_t *plb_data(const uint8_t *d, size_t len);
plb_t *plb_dict_set(plb_t *dict, const char *key, plb_t *value);
plb_t *plb_array_add(plb_t *array, plb_t *value);
void plb_free(plb_t *node);

// (de)serialization, the encoded buffer is malloc'd
uint8_t *plb_encode(const plb_t *root, size_t *len);
plb_t *plb_decode(const uint8_t *buf, size_t len);

// accessors
plb_t *plb_get(const plb_t *dict, const char *key);
plb_t *plb_at(const plb_t *container, int index);
bool plb_get_int(const plb_t *dict, const char *key, int64_t *v);
const char *plb_get_string(const plb_t *dict, const char *key);

// human readable one-liner (malloc'd), for logs
char *plb_dump(const plb_t *node);
