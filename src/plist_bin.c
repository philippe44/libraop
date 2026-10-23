/*
 *  plist_bin - small binary plist (bplist00) reader & writer with nesting,
 *  enough for the AirPlay 2 SETUP/info exchanges
 *
 *  See LICENSE
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdarg.h>

#include "plist_bin.h"

#define PLB_MAX_DEPTH	16
#define PLB_MAX_OBJECTS	100000

/*----------------------------------------------------------------------------*/
/* tree building                                                              */
/*----------------------------------------------------------------------------*/
static plb_t *plb_new(plb_type_t type) {
	plb_t *n = calloc(1, sizeof(plb_t));
	if (n) n->type = type;
	return n;
}

plb_t *plb_dict(void) { return plb_new(PLB_DICT); }
plb_t *plb_array(void) { return plb_new(PLB_ARRAY); }

plb_t *plb_string(const char *s) {
	plb_t *n = plb_new(PLB_STRING);
	if (n) n->s = strdup(s ? s : "");
	return n;
}

plb_t *plb_int(int64_t v) {
	plb_t *n = plb_new(PLB_INT);
	if (n) n->i = v;
	return n;
}

plb_t *plb_bool(bool v) {
	plb_t *n = plb_new(PLB_BOOL);
	if (n) n->b = v;
	return n;
}

plb_t *plb_data(const uint8_t *d, size_t len) {
	plb_t *n = plb_new(PLB_DATA);
	if (n) {
		n->data = malloc(len ? len : 1);
		if (len) memcpy(n->data, d, len);
		n->len = len;
	}
	return n;
}

static void plb_append(plb_t *parent, plb_t *child) {
	plb_t **p = &parent->children;
	while (*p) p = &(*p)->next;
	child->next = NULL;
	*p = child;
	parent->count++;
}

plb_t *plb_dict_set(plb_t *dict, const char *key, plb_t *value) {
	if (!dict || !value || !key || dict->type != PLB_DICT) {
		plb_free(value);
		return dict;
	}

	// replace an existing member
	for (plb_t **p = &dict->children; *p; p = &(*p)->next) {
		if ((*p)->key && !strcmp((*p)->key, key)) {
			plb_t *old = *p;
			*p = old->next;
			dict->count--;
			old->next = NULL;
			plb_free(old);
			break;
		}
	}

	value->key = strdup(key);
	plb_append(dict, value);
	return dict;
}

plb_t *plb_array_add(plb_t *array, plb_t *value) {
	if (!array || !value || array->type != PLB_ARRAY) {
		plb_free(value);
		return array;
	}
	plb_append(array, value);
	return array;
}

void plb_free(plb_t *node) {
	if (!node) return;
	plb_t *c = node->children;
	while (c) {
		plb_t *next = c->next;
		plb_free(c);
		c = next;
	}
	free(node->key);
	free(node->s);
	free(node->data);
	free(node);
}

/*----------------------------------------------------------------------------*/
/* accessors                                                                  */
/*----------------------------------------------------------------------------*/
plb_t *plb_get(const plb_t *dict, const char *key) {
	if (!dict || !key || dict->type != PLB_DICT) return NULL;
	for (plb_t *c = dict->children; c; c = c->next) {
		if (c->key && !strcmp(c->key, key)) return c;
	}
	return NULL;
}

plb_t *plb_at(const plb_t *container, int index) {
	if (!container || index < 0 || (container->type != PLB_ARRAY && container->type != PLB_DICT)) return NULL;
	plb_t *c = container->children;
	while (c && index--) c = c->next;
	return c;
}

bool plb_get_int(const plb_t *dict, const char *key, int64_t *v) {
	plb_t *n = plb_get(dict, key);
	if (!n) return false;
	switch (n->type) {
		case PLB_INT: *v = n->i; return true;
		case PLB_BOOL: *v = n->b; return true;
		case PLB_REAL: *v = (int64_t) n->r; return true;
		default: return false;
	}
}

const char *plb_get_string(const plb_t *dict, const char *key) {
	plb_t *n = plb_get(dict, key);
	return (n && n->type == PLB_STRING) ? n->s : NULL;
}

/*----------------------------------------------------------------------------*/
/* growing output buffer                                                      */
/*----------------------------------------------------------------------------*/
typedef struct {
	uint8_t *buf;
	size_t len, cap;
} wbuf_t;

static bool wb_put(wbuf_t *w, const void *data, size_t n) {
	if (w->len + n > w->cap) {
		size_t cap = w->cap ? w->cap * 2 : 256;
		while (cap < w->len + n) cap *= 2;
		uint8_t *tmp = realloc(w->buf, cap);
		if (!tmp) return false;
		w->buf = tmp;
		w->cap = cap;
	}
	memcpy(w->buf + w->len, data, n);
	w->len += n;
	return true;
}

static bool wb_byte(wbuf_t *w, uint8_t b) {
	return wb_put(w, &b, 1);
}

static void wb_be(wbuf_t *w, uint64_t v, int size) {
	for (int i = size - 1; i >= 0; i--) wb_byte(w, (uint8_t) (v >> (8 * i)));
}

static void wb_printf(wbuf_t *w, const char *fmt, ...) {
	char tmp[512];
	va_list args;
	va_start(args, fmt);
	int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
	va_end(args);
	if (n > 0) wb_put(w, tmp, n < (int) sizeof(tmp) ? n : (int) sizeof(tmp) - 1);
}

/*----------------------------------------------------------------------------*/
/* encoder                                                                    */
/*----------------------------------------------------------------------------*/
typedef struct {
	const plb_t *node;
	const char *key;	// non-NULL => this object is the key string of 'node'
} plb_obj_t;

static int plb_count_objects(const plb_t *n) {
	int count = 1;
	if (n->type == PLB_DICT) count += n->count;
	if (n->type == PLB_DICT || n->type == PLB_ARRAY) {
		for (plb_t *c = n->children; c; c = c->next) count += plb_count_objects(c);
	}
	return count;
}

static void plb_flatten(const plb_t *n, plb_obj_t *objs, int *idx) {
	objs[(*idx)++] = (plb_obj_t) { n, NULL };
	if (n->type == PLB_DICT) {
		for (plb_t *c = n->children; c; c = c->next) objs[(*idx)++] = (plb_obj_t) { c, c->key ? c->key : "" };
	}
	if (n->type == PLB_DICT || n->type == PLB_ARRAY) {
		for (plb_t *c = n->children; c; c = c->next) plb_flatten(c, objs, idx);
	}
}

static int plb_find(const plb_obj_t *objs, int nobj, const plb_t *node, bool key) {
	for (int i = 0; i < nobj; i++) {
		if (objs[i].node == node && (objs[i].key != NULL) == key) return i;
	}
	return 0;
}

static int plb_int_size(uint64_t v) {
	if (v < 256) return 1;
	if (v < 65536) return 2;
	if (v <= 0xffffffffULL) return 4;
	return 8;
}

static void wb_count(wbuf_t *w, uint8_t marker, uint64_t count) {
	if (count < 15) {
		wb_byte(w, marker | (uint8_t) count);
	} else {
		int size = plb_int_size(count);
		wb_byte(w, marker | 0x0f);
		wb_byte(w, 0x10 | (size == 1 ? 0 : size == 2 ? 1 : size == 4 ? 2 : 3));
		wb_be(w, count, size);
	}
}

static void wb_int(wbuf_t *w, int64_t v) {
	if (v < 0) {
		wb_byte(w, 0x13);
		wb_be(w, (uint64_t) v, 8);
	} else {
		int size = plb_int_size((uint64_t) v);
		wb_byte(w, 0x10 | (size == 1 ? 0 : size == 2 ? 1 : size == 4 ? 2 : 3));
		wb_be(w, (uint64_t) v, size);
	}
}

static void wb_string(wbuf_t *w, const char *s) {
	size_t n = strlen(s), m = 0;
	bool ascii = true;
	uint16_t *u;

	for (size_t i = 0; i < n; i++) if ((uint8_t) s[i] >= 0x80) ascii = false;

	if (ascii) {
		wb_count(w, 0x50, n);
		wb_put(w, s, n);
		return;
	}

	// UTF-8 to UTF-16BE
	u = malloc((n + 1) * 2 * sizeof(uint16_t));
	for (size_t i = 0; i < n;) {
		uint8_t c = s[i];
		uint32_t cp;
		if (c < 0x80) { cp = c; i++; }
		else if ((c & 0xe0) == 0xc0 && i + 1 < n) { cp = ((c & 0x1f) << 6) | (s[i+1] & 0x3f); i += 2; }
		else if ((c & 0xf0) == 0xe0 && i + 2 < n) { cp = ((c & 0x0f) << 12) | ((s[i+1] & 0x3f) << 6) | (s[i+2] & 0x3f); i += 3; }
		else if ((c & 0xf8) == 0xf0 && i + 3 < n) { cp = ((c & 0x07) << 18) | ((s[i+1] & 0x3f) << 12) | ((s[i+2] & 0x3f) << 6) | (s[i+3] & 0x3f); i += 4; }
		else { cp = '?'; i++; }
		if (cp >= 0x10000) {
			cp -= 0x10000;
			u[m++] = 0xd800 | (cp >> 10);
			u[m++] = 0xdc00 | (cp & 0x3ff);
		} else u[m++] = cp;
	}

	wb_count(w, 0x60, m);
	for (size_t i = 0; i < m; i++) wb_be(w, u[i], 2);
	free(u);
}

static void plb_encode_object(wbuf_t *w, const plb_obj_t *objs, int nobj, int refsize, int idx) {
	const plb_t *n = objs[idx].node;

	if (objs[idx].key) {
		wb_string(w, objs[idx].key);
		return;
	}

	switch (n->type) {
		case PLB_NULL:
			wb_byte(w, 0x00);
			break;
		case PLB_BOOL:
			wb_byte(w, n->b ? 0x09 : 0x08);
			break;
		case PLB_INT:
			wb_int(w, n->i);
			break;
		case PLB_REAL: {
			uint64_t bits;
			memcpy(&bits, &n->r, sizeof(bits));
			wb_byte(w, 0x23);
			wb_be(w, bits, 8);
			break;
		}
		case PLB_STRING:
			wb_string(w, n->s ? n->s : "");
			break;
		case PLB_DATA:
			wb_count(w, 0x40, n->len);
			wb_put(w, n->data, n->len);
			break;
		case PLB_ARRAY:
			wb_count(w, 0xa0, n->count);
			for (plb_t *c = n->children; c; c = c->next) wb_be(w, plb_find(objs, nobj, c, false), refsize);
			break;
		case PLB_DICT:
			wb_count(w, 0xd0, n->count);
			for (plb_t *c = n->children; c; c = c->next) wb_be(w, plb_find(objs, nobj, c, true), refsize);
			for (plb_t *c = n->children; c; c = c->next) wb_be(w, plb_find(objs, nobj, c, false), refsize);
			break;
	}
}

uint8_t *plb_encode(const plb_t *root, size_t *len) {
	wbuf_t w = { 0 };
	uint8_t trailer[32] = { 0 };
	int nobj, idx = 0, refsize, ofssize;
	plb_obj_t *objs;
	uint64_t *offsets, table;

	*len = 0;
	if (!root) return NULL;

	nobj = plb_count_objects(root);
	objs = calloc(nobj, sizeof(plb_obj_t));
	offsets = calloc(nobj, sizeof(uint64_t));
	if (!objs || !offsets) {
		free(objs);
		free(offsets);
		return NULL;
	}

	plb_flatten(root, objs, &idx);
	refsize = plb_int_size(nobj);

	wb_put(&w, "bplist00", 8);
	for (int i = 0; i < nobj; i++) {
		offsets[i] = w.len;
		plb_encode_object(&w, objs, nobj, refsize, i);
	}

	table = w.len;
	ofssize = plb_int_size(table);
	for (int i = 0; i < nobj; i++) wb_be(&w, offsets[i], ofssize);

	trailer[6] = ofssize;
	trailer[7] = refsize;
	for (int i = 0; i < 8; i++) {
		trailer[8 + i] = (uint8_t) ((uint64_t) nobj >> (8 * (7 - i)));
		trailer[24 + i] = (uint8_t) (table >> (8 * (7 - i)));
	}
	wb_put(&w, trailer, sizeof(trailer));

	free(objs);
	free(offsets);
	*len = w.len;
	return w.buf;
}

/*----------------------------------------------------------------------------*/
/* decoder                                                                    */
/*----------------------------------------------------------------------------*/
typedef struct {
	const uint8_t *buf;
	size_t len;
	int ofssize, refsize;
	uint64_t nobj, top, table;
} rctx_t;

static uint64_t rd_be(const uint8_t *p, int size) {
	uint64_t v = 0;
	for (int i = 0; i < size; i++) v = (v << 8) | p[i];
	return v;
}

static bool rd_offset(rctx_t *c, uint64_t idx, size_t *ofs) {
	if (idx >= c->nobj) return false;
	size_t pos = c->table + idx * c->ofssize;
	if (pos + c->ofssize > c->len) return false;
	*ofs = rd_be(c->buf + pos, c->ofssize);
	return *ofs < c->len;
}

static bool rd_count(rctx_t *c, size_t *pos, uint8_t low, uint64_t *count) {
	if (low != 0x0f) {
		*count = low;
		return true;
	}
	if (*pos >= c->len) return false;
	uint8_t m = c->buf[(*pos)++];
	if ((m & 0xf0) != 0x10) return false;
	int size = 1 << (m & 0x0f);
	if (size > 8 || *pos + size > c->len) return false;
	*count = rd_be(c->buf + *pos, size);
	*pos += size;
	return true;
}

static size_t utf8_put(char *out, uint32_t cp) {
	if (cp < 0x80) { out[0] = cp; return 1; }
	if (cp < 0x800) { out[0] = 0xc0 | (cp >> 6); out[1] = 0x80 | (cp & 0x3f); return 2; }
	if (cp < 0x10000) { out[0] = 0xe0 | (cp >> 12); out[1] = 0x80 | ((cp >> 6) & 0x3f); out[2] = 0x80 | (cp & 0x3f); return 3; }
	out[0] = 0xf0 | (cp >> 18); out[1] = 0x80 | ((cp >> 12) & 0x3f); out[2] = 0x80 | ((cp >> 6) & 0x3f); out[3] = 0x80 | (cp & 0x3f);
	return 4;
}

static plb_t *rd_object(rctx_t *c, uint64_t idx, int depth) {
	size_t pos;
	uint64_t count;
	plb_t *n;

	if (depth > PLB_MAX_DEPTH || !rd_offset(c, idx, &pos)) return NULL;

	uint8_t marker = c->buf[pos++];
	uint8_t type = marker >> 4, low = marker & 0x0f;

	switch (type) {
		case 0x0:
			if (low == 8) return plb_bool(false);
			if (low == 9) return plb_bool(true);
			return plb_new(PLB_NULL);
		case 0x1: {
			int size = 1 << low;
			if (size > 8 || pos + size > c->len) return NULL;
			return plb_int((int64_t) rd_be(c->buf + pos, size));
		}
		case 0x2: {
			int size = 1 << low;
			if ((size != 4 && size != 8) || pos + size > c->len) return NULL;
			n = plb_new(PLB_REAL);
			if (size == 4) {
				uint32_t bits = rd_be(c->buf + pos, 4);
				float f;
				memcpy(&f, &bits, sizeof(f));
				n->r = f;
			} else {
				uint64_t bits = rd_be(c->buf + pos, 8);
				memcpy(&n->r, &bits, sizeof(n->r));
			}
			return n;
		}
		case 0x3: {
			if (pos + 8 > c->len) return NULL;
			uint64_t bits = rd_be(c->buf + pos, 8);
			n = plb_new(PLB_REAL);
			memcpy(&n->r, &bits, sizeof(n->r));
			return n;
		}
		case 0x4:
			if (!rd_count(c, &pos, low, &count) || count > c->len || pos + count > c->len) return NULL;
			return plb_data(c->buf + pos, count);
		case 0x5:
			if (!rd_count(c, &pos, low, &count) || count > c->len || pos + count > c->len) return NULL;
			n = plb_new(PLB_STRING);
			n->s = malloc(count + 1);
			memcpy(n->s, c->buf + pos, count);
			n->s[count] = '\0';
			return n;
		case 0x6: {
			if (!rd_count(c, &pos, low, &count) || count > c->len || pos + count * 2 > c->len) return NULL;
			n = plb_new(PLB_STRING);
			n->s = malloc(count * 3 + 1);
			size_t o = 0;
			for (uint64_t i = 0; i < count; i++) {
				uint32_t cp = rd_be(c->buf + pos + 2 * i, 2);
				if (cp >= 0xd800 && cp < 0xdc00 && i + 1 < count) {
					uint32_t lo = rd_be(c->buf + pos + 2 * (i + 1), 2);
					if (lo >= 0xdc00 && lo < 0xe000) {
						cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
						i++;
					}
				}
				o += utf8_put(n->s + o, cp);
			}
			n->s[o] = '\0';
			return n;
		}
		case 0x8: {
			int size = low + 1;
			if (pos + size > c->len) return NULL;
			return plb_int((int64_t) rd_be(c->buf + pos, size));
		}
		case 0xa:
		case 0xc: {
			if (!rd_count(c, &pos, low, &count) || count > c->nobj || pos + count * c->refsize > c->len) return NULL;
			n = plb_array();
			for (uint64_t i = 0; i < count; i++) {
				plb_t *child = rd_object(c, rd_be(c->buf + pos + i * c->refsize, c->refsize), depth + 1);
				if (!child) {
					plb_free(n);
					return NULL;
				}
				plb_append(n, child);
			}
			return n;
		}
		case 0xd: {
			if (!rd_count(c, &pos, low, &count) || count > c->nobj || pos + count * 2 * c->refsize > c->len) return NULL;
			n = plb_dict();
			for (uint64_t i = 0; i < count; i++) {
				plb_t *key = rd_object(c, rd_be(c->buf + pos + i * c->refsize, c->refsize), depth + 1);
				plb_t *val = rd_object(c, rd_be(c->buf + pos + (count + i) * c->refsize, c->refsize), depth + 1);
				if (!key || !val || key->type != PLB_STRING) {
					plb_free(key);
					plb_free(val);
					plb_free(n);
					return NULL;
				}
				val->key = key->s;
				key->s = NULL;
				plb_free(key);
				plb_append(n, val);
			}
			return n;
		}
		default:
			return NULL;
	}
}

plb_t *plb_decode(const uint8_t *buf, size_t len) {
	rctx_t c;

	if (!buf || len < 8 + 32 || memcmp(buf, "bplist0", 7)) return NULL;

	const uint8_t *t = buf + len - 32;
	c.buf = buf;
	c.len = len;
	c.ofssize = t[6];
	c.refsize = t[7];
	c.nobj = rd_be(t + 8, 8);
	c.top = rd_be(t + 16, 8);
	c.table = rd_be(t + 24, 8);

	if (!c.ofssize || c.ofssize > 8 || !c.refsize || c.refsize > 8) return NULL;
	if (!c.nobj || c.nobj > PLB_MAX_OBJECTS || c.top >= c.nobj) return NULL;
	if (c.table < 8 || c.table >= len - 32 || c.table + c.nobj * c.ofssize > len - 32) return NULL;

	return rd_object(&c, c.top, 0);
}

/*----------------------------------------------------------------------------*/
/* debug dump                                                                 */
/*----------------------------------------------------------------------------*/
static void plb_dump_rec(wbuf_t *w, const plb_t *n, int depth) {
	if (!n || depth > PLB_MAX_DEPTH) return;
	if (n->key) wb_printf(w, "%s: ", n->key);
	switch (n->type) {
		case PLB_NULL: wb_printf(w, "null"); break;
		case PLB_BOOL: wb_printf(w, n->b ? "true" : "false"); break;
		case PLB_INT: wb_printf(w, "%" PRId64, n->i); break;
		case PLB_REAL: wb_printf(w, "%g", n->r); break;
		case PLB_STRING: wb_printf(w, "\"%s\"", n->s ? n->s : ""); break;
		case PLB_DATA: wb_printf(w, "<%zu bytes>", n->len); break;
		case PLB_ARRAY:
		case PLB_DICT:
			wb_printf(w, n->type == PLB_ARRAY ? "[" : "{");
			for (plb_t *c = n->children; c; c = c->next) {
				plb_dump_rec(w, c, depth + 1);
				if (c->next) wb_printf(w, ", ");
			}
			wb_printf(w, n->type == PLB_ARRAY ? "]" : "}");
			break;
	}
}

char *plb_dump(const plb_t *node) {
	wbuf_t w = { 0 };
	plb_dump_rec(&w, node, 0);
	wb_byte(&w, 0);
	return (char*) w.buf;
}
