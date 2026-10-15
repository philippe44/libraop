/*
 * pair_ap's "fruit" (legacy AppleTV) pairing needs libplist and is not used
 * here (libraop has its own implementation in pairing.cpp), but pair.c
 * references the definition, so provide an empty one.
 */

#include "pair-internal.h"

struct pair_definition pair_client_fruit = { 0 };
