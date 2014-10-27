#ifndef DES_H
#define DES_H

#include <stdint.h>

#include "..\import.h"

#define rotl32(x,n)   (((x) << ((uint32_t)(n))) | ((x) >> (32 - (uint32_t)(n))))
#define rotr32(x,n)   (((x) >> ((uint32_t)(n))) | ((x) << (32 - (uint32_t)(n))))

#define byteswap32(x)	((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))

#define Bzero(x, y) pMemset(x, 0, y)

typedef struct des_key {
	char kn[16][8];
	uint32_t sp[8][64];
	char iperm[16][16][8];
	char fperm[16][16][8];
} DES_KEY;

int _mcrypt_set_key(DES_KEY * dkey, char *user_key, int len);
void _mcrypt_encrypt(DES_KEY * key, char *block);

#endif