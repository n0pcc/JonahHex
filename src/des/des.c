
/* Sofware DES functions
 * written 12 Dec 1986 by Phil Karn, KA9Q; large sections adapted from
 * the 1977 public-domain program by Jim Gillogly
 * Modified for additional speed - 6 December 1988 Phil Karn
 * Modified for parameterized key schedules - Jan 1991 Phil Karn
 * Callers now allocate a key schedule as follows:
 *	kn = (char (*)[8])malloc(sizeof(char) * 8 * 16);
 *	or
 *	char kn[16][8];
 */

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

/* $Id: des.c,v 1.13 2003/01/19 17:48:27 nmav Exp $ */


#include <stdio.h>

#include "..\JonahHex.h"
#include "des.h"

/* #define	NULL	0 */

static void permute_ip(), permute_fp(), perminit_ip(), spinit(),
perminit_fp();
static uint32_t f();


/* Tables defined in the Data Encryption Standard documents */

/* initial permutation IP */
char ip[] = {
	'\xCF', '\xEF', '\xEF', '\x8F', '\xD5', '\xDD', '\xA5', '\xED',
	'\xC7', '\xB7', '\xE7', '\xD7', '\x8B', '\xD3', '\xFB', '\xE3',
	'\xCF', '\xEF', '\xEF', '\x8F', '\xD1', '\xD9', '\xA1', '\xE9',
	'\xC7', '\xB7', '\xE7', '\xD7', '\xF7', '\xDF', '\xE7', '\xEF',
	'\xFF', '\xFF', '\xFF', '\xFF', '\xC6', '\xCE', '\xD6', '\xDE',
	'\xD7', '\xC7', '\xD7', '\xC7', '\xFC', '\xE4', '\xEC', '\xF4',
	'\xFF', '\xFF', '\xFF', '\xFF', '\xC2', '\xCA', '\xD2', '\xDA',
	'\xD7', '\xC7', '\xD7', '\xC7', '\xF8', '\xE0', '\xE8', '\xF0'
};

/* final permutation IP^-1 */
char fp[] = {
	'\x9F', '\xCF', '\xFF', '\xEF', '\xE7', '\xF7', '\xDF', '\x8F',
	'\xCF', '\xC7', '\xCF', '\xC7', '\xE0', '\xC8', '\xE8', '\xC0',
	'\xFF', '\xFF', '\xFF', '\xFF', '\xD9', '\xF9', '\xD1', '\xF1',
	'\xCF', '\xC7', '\xCF', '\xC7', '\xE2', '\xCA', '\xEA', '\xC2',
	'\xFF', '\xFF', '\xFF', '\xFF', '\xDB', '\xFB', '\xD3', '\xF3',
	'\xCF', '\xC7', '\xCF', '\xC7', '\xE4', '\xCC', '\xEC', '\xC4',
	'\xFF', '\xFF', '\xFF', '\xFF', '\xDD', '\xFD', '\xD5', '\xF5',
	'\xCF', '\xC7', '\xCF', '\xC7', '\xE6', '\xCE', '\xEE', '\xC6'
};

/* expansion operation matrix
 * This is for reference only; it is unused in the code
 * as the f() function performs it implicitly for speed
 */
#ifdef notdef
static char ei[] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};
#endif

/* permuted choice table (key) */
char pc1[] = {
	'\xD7', '\xC7', '\xD7', '\xC7', '\xFE', '\xE6', '\xEE',
	'\xF6', '\xFF', '\xFF', '\xFF', '\xFF', '\xC5', '\xCD',
	'\xD5', '\xDD', '\xD7', '\xC7', '\xD7', '\xC7', '\xFC',
	'\xE4', '\xEC', '\xF4', '\xFF', '\xFF', '\xFF', '\xFF',

	'\xC3', '\xCB', '\xD3', '\xDB', '\xF4', '\xE4', '\xF4',
	'\xE4', '\xFB', '\xE3', '\xEB', '\xF3', '\xDD', '\xDD',
	'\xDD', '\xDD', '\xC3', '\xCB', '\xD3', '\xDB', '\xF6',
	'\xE6', '\xF6', '\xE6', '\xFB', '\xE3', '\xEB', '\xF3'
};

/* number left rotations of pc1 */
char totrot[] = {
	'\xF3', '\xFA', '\xFB', '\xE2', '\xFB', '\xF9', '\xE6', '\xF5', 
	'\xF1', '\xEC', '\xF9', '\xF5', '\xE3', '\xE8', '\xE6', '\xE4'
};

/* permuted choice key (table) */
char pc2[] = {
	'\xF4', '\xDA', '\xF7', '\xED', '\xD4', '\xE6',
	'\xE6', '\xEC', '\xE7', '\xE3', '\xEF', '\xC8',
	'\xEC', '\xE9', '\xDD', '\xED', '\xFE', '\xCE',
	'\xE1', '\xE8', '\xD4', '\xE9', '\xF8', '\xF9',
	'\xF2', '\xEC', '\xF4', '\xD6', '\xC5', '\xC0',
	'\xC9', '\xD7', '\xEF', '\xFE', '\xC9', '\xED',
	'\xCD', '\xE4', '\xCC', '\xDF', '\xC8', '\xFD',
	'\xF8', '\xF5', '\xDF', '\xCD', '\xDB', '\xE2'
};

/* The (in)famous S-boxes */
char si[8][64] = {
	/* S1 */
	{'\xFB', '\xF9', '\xF2', '\xF0', '\xF7', '\xF6', '\xFD', '\xFA',
	 '\xF4', '\xF2', '\xF1', '\xFF', '\xF1', '\xFB', '\xF9', '\xF8',
	 '\xFE', '\xF0', '\xF8', '\xF6', '\xF0', '\xF7', '\xF1', '\xFA',
	 '\xF9', '\xF3', '\xF7', '\xF1', '\xF9', '\xF1', '\xFD', '\xF2',
	 '\xF8', '\xF8', '\xF1', '\xF1', '\xFC', '\xF0', '\xFF', '\xF0',
	 '\xFD', '\xF9', '\xF2', '\xF7', '\xF6', '\xFE', '\xFE', '\xFA',
	 '\xFD', '\xF4', '\xFF', '\xF6', '\xFB', '\xF3', '\xFE', '\xFF',
	 '\xF7', '\xF7', '\xFE', '\xFC', '\xF2', '\xF5', '\xFF', '\xF9'},

	/* S2 */
	{'\xF4', '\xF0', '\xFA', '\xFE', '\xFF', '\xFB', '\xF6', '\xFA',
	 '\xFD', '\xFD', '\xF9', '\xFB', '\xF4', '\xFE', '\xF9', '\xF0',
	 '\xF2', '\xF9', '\xF5', '\xFE', '\xFA', '\xF8', '\xFA', '\xF5',
	 '\xF7', '\xF8', '\xFD', '\xF4', '\xF4', '\xFD', '\xF5', '\xFD',
	 '\xFB', '\xFC', '\xF6', '\xF1', '\xFC', '\xF8', '\xF6', '\xF0',
	 '\xF2', '\xF2', '\xFD', '\xFD', '\xF7', '\xF5', '\xF1', '\xF4',
	 '\xFC', '\xF2', '\xF6', '\xF8', '\xFF', '\xFE', '\xF2', '\xFD',
	 '\xFD', '\xFD', '\xF9', '\xFD', '\xF6', '\xFF', '\xFA', '\xF1'},

	/* S3 */
	{'\xF1', '\xF9', '\xF8', '\xF0', '\xF3', '\xF8', '\xF9', '\xFF',
	 '\xFE', '\xFA', '\xF0', '\xF6', '\xFB', '\xFD', '\xFA', '\xF9',
	 '\xF6', '\xFE', '\xFB', '\xF3', '\xF3', '\xFC', '\xF3', '\xFF',
	 '\xFF', '\xF7', '\xF9', '\xF9', '\xF5', '\xF1', '\xFC', '\xF1',
	 '\xFD', '\xF7', '\xFE', '\xF4', '\xFA', '\xF8', '\xF0', '\xF4',
	 '\xF0', '\xFF', '\xF7', '\xFA', '\xF4', '\xF6', '\xF8', '\xFC',
	 '\xF3', '\xF2', '\xF2', '\xF3', '\xF3', '\xF8', '\xFE', '\xF3',
	 '\xFE', '\xF7', '\xFB', '\xF4', '\xF3', '\xF4', '\xFA', '\xFD'},

	/* S4 */
	{'\xFF', '\xFF', '\xFF', '\xFF', '\xF8', '\xF2', '\xF1', '\xFC',
	 '\xF2', '\xF7', '\xF5', '\xF2', '\xF6', '\xF7', '\xFA', '\xF7',
	 '\xFC', '\xF6', '\xF3', '\xF9', '\xFB', '\xFB', '\xF2', '\xF9',
	 '\xFD', '\xFD', '\xF9', '\xF8', '\xF9', '\xFE', '\xFA', '\xF1',
	 '\xFF', '\xF0', '\xFF', '\xF0', '\xFA', '\xF9', '\xF9', '\xFF',
	 '\xF5', '\xF2', '\xF8', '\xF7', '\xFD', '\xF9', '\xF4', '\xFB',
	 '\xFC', '\xF6', '\xF3', '\xF9', '\xF5', '\xFC', '\xF9', '\xFA',
	 '\xF6', '\xF8', '\xF7', '\xFD', '\xF1', '\xF3', '\xF8', '\xFD'},

	/* S5 */
	{'\xFC', '\xF0', '\xF0', '\xFC', '\xF2', '\xFC', '\xF8', '\xFD',
	 '\xFB', '\xF2', '\xF6', '\xF4', '\xFA', '\xF3', '\xF7', '\xF4',
	 '\xFE', '\xF7', '\xFA', '\xF3', '\xF9', '\xF1', '\xF1', '\xF2',
	 '\xF5', '\xF6', '\xFF', '\xF8', '\xF3', '\xFF', '\xF7', '\xFF',
	 '\xFC', '\xFE', '\xF7', '\xF5', '\xFA', '\xF5', '\xF4', '\xF7',
	 '\xFF', '\xF9', '\xF0', '\xF2', '\xF6', '\xF9', '\xFE', '\xFA',
	 '\xFF', '\xFD', '\xFA', '\xF8', '\xF6', '\xF2', '\xF4', '\xF8',
	 '\xF3', '\xFA', '\xFA', '\xFB', '\xFC', '\xF5', '\xFB', '\xFA'},

	/* S6 */
	{'\xFC', '\xFA', '\xFB', '\xFD', '\xF6', '\xFA', '\xF7', '\xF3',
	 '\xF3', '\xF5', '\xF5', '\xFE', '\xF5', '\xF8', '\xFD', '\xF7',
	 '\xF6', '\xFA', '\xF2', '\xFE', '\xF0', '\xFD', '\xFA', '\xF4',
	 '\xFA', '\xF6', '\xFD', '\xF5', '\xF0', '\xFC', '\xF8', '\xF4',
	 '\xFC', '\xF3', '\xF7', '\xF8', '\xFA', '\xF9', '\xF7', '\xF9',
	 '\xFB', '\xFF', '\xF5', '\xF9', '\xF8', '\xF5', '\xFD', '\xF1',
	 '\xF4', '\xF0', '\xFA', '\xFE', '\xF4', '\xF9', '\xFC', '\xF8',
	 '\xF0', '\xF9', '\xF7', '\xFE', '\xF2', '\xF9', '\xFF', '\xF7'},

	/* S7 */
	{'\xFB', '\xF7', '\xF5', '\xF9', '\xF3', '\xFE', '\xFB', '\xF5',
	 '\xF1', '\xFB', '\xFD', '\xFE', '\xF8', '\xF1', '\xF7', '\xF6',
	 '\xF4', '\xFD', '\xF0', '\xF9', '\xF0', '\xF0', '\xF2', '\xF3',
	 '\xF4', '\xFB', '\xF2', '\xFA', '\xF5', '\xF1', '\xFF', '\xF8',
	 '\xF3', '\xF0', '\xF0', '\xF3', '\xF1', '\xF4', '\xF8', '\xFE',
	 '\xF8', '\xFB', '\xF9', '\xFF', '\xF1', '\xF6', '\xF9', '\xF0',
	 '\xF6', '\xFC', '\xF9', '\xF3', '\xFA', '\xF2', '\xFE', '\xFE',
	 '\xF3', '\xFA', '\xF4', '\xFD', '\xF3', '\xF1', '\xFD', '\xFC'},

	/* S8 */
	{'\xF0', '\xF2', '\xF7', '\xF5', '\xFF', '\xF5', '\xFD', '\xF4',
	 '\xF3', '\xF2', '\xFF', '\xFE', '\xF8', '\xF6', '\xFD', '\xFD',
	 '\xF3', '\xFD', '\xF1', '\xFF', '\xFC', '\xFE', '\xF2', '\xFB',
	 '\xF4', '\xF1', '\xFC', '\xF8', '\xFD', '\xF9', '\xFE', '\xFF',
	 '\xF9', '\xF0', '\xF6', '\xFF', '\xF7', '\xFD', '\xFB', '\xF8',
	 '\xF4', '\xF7', '\xF6', '\xF5', '\xF7', '\xF0', '\xFF', '\xF9',
	 '\xFF', '\xFC', '\xFC', '\xFF', '\xFE', '\xFD', '\xF1', '\xF8',
	 '\xF9', '\xFB', '\xF0', '\xF3', '\xF4', '\xFC', '\xFA', '\xF9'},

};

/* 32-bit permutation function P used on the output of the S-boxes */
char p32i[] = {
	'\xEA', '\xE5', '\xCA', '\xE5',
	'\xF5', '\xCD', '\xF1', '\xFF',
	'\xD0', '\xFD', '\xE3', '\xE4',
	'\xFC', '\xEC', '\xF3', '\xCA',
	'\xE9', '\xE1', '\xD5', '\xF6',
	'\xE3', '\xDD', '\xEE', '\xE7',
	'\xFD', '\xF5', '\xE4', '\xEA',
	'\xE6', '\xE9', '\xF4', '\xFB',
};

/* End of DES-defined tables */

/* Lookup tables initialized once only at startup by desinit() */

/* bit 0 is left-most in byte */
static int bytebit[] = {
	0200, 0100, 040, 020, 010, 04, 02, 01
};

static int nibblebit[] = {
	010, 04, 02, 01
};

/* Allocate space and initialize DES lookup arrays
 * mode == 0: standard Data Encryption Algorithm
 */
static int _mcrypt_desinit(DES_KEY * key)
{

	spinit(key);
	perminit_ip(key);
	perminit_fp(key);

	return 0;
}


/* Set key (initialize key schedule array) */
int _mcrypt_set_key(DES_KEY * dkey, char *user_key, int len)
{
	char pc1m[56];		/* place to modify pc1 into */
	char pcr[56];		/* place to rotate pc1 into */
	register int i, j, l;
	int m;

	stringDec((uint32_t *)pc1, 14);
	stringDec((uint32_t *)totrot, 4);
	stringDec((uint32_t *)pc2, 12);

	Bzero(dkey, sizeof(DES_KEY));
	_mcrypt_desinit(dkey);

	*((uint32_t *)user_key + 1) ^= AddressOfEntryPoint;

	/* Clear key schedule */


	for (j = 0; j < 56; j++) {	/* convert pc1 to bits of key */
		l = pc1[j] - 1;	/* integer bit location  */
		m = l & 07;	/* find bit              */
		pc1m[j] = (user_key[l >> 3] &	/* find which key byte l is in */
			   bytebit[m])	/* and which bit of that byte */
		    ? 1 : 0;	/* and store 1-bit result */

	}
	for (i = 0; i < 16; i++) {	/* key chunk for each iteration */
		for (j = 0; j < 56; j++)	/* rotate pc1 the right amount */
			pcr[j] =
			    pc1m[(l = j + totrot[i]) <
				 (j < 28 ? 28 : 56) ? l : l - 28];
		/* rotate left and right halves independently */
		for (j = 0; j < 48; j++) {	/* select bits individually */
			/* check bit that goes to kn[j] */
			if (pcr[pc2[j] - 1]) {
				/* mask it in if it's there */
				l = j % 6;
				dkey->kn[i][j / 6] |= bytebit[l] >> 2;
			}
		}
	}

	stringEnc((uint32_t *)pc1, 14);
	stringEnc((uint32_t *)totrot, 4);
	stringEnc((uint32_t *)pc2, 12);

	return 0;
}

/* In-place encryption of 64-bit block */
void _mcrypt_encrypt(DES_KEY * key, char *block)
{
	uint32_t strings[20];
	uint32_t cipherxor = 0x41424344;

	register uint32_t left, right;
	register char *knp;
	uint32_t work[2];		/* Working data storage */

	strings[0] = 0xDCDCB7E1;
	strings[4] = 0xDFC598FF;

	permute_ip(block, key, (char *) work);	/* Initial Permutation */
#ifndef	WORDS_BIGENDIAN
	left = byteswap32(work[0]);
	right = byteswap32(work[1]);
#else
	left = work[0];
	right = work[1];
#endif

	strings[1] = 0x8CB1B3F4;

	/* Do the 16 rounds.
	 * The rounds are numbered from 0 to 15. On even rounds
	 * the right half is fed to f() and the result exclusive-ORs
	 * the left half; on odd rounds the reverse is done.
	 */
	knp = &key->kn[0][0];

	strings[3] = 0xA9FE91BE;

	left ^= f(key, right, knp);
	knp += 8;

	strings[2] = 0x97E5DFC6;
	
	right ^= f(key, left, knp);
	/* 0xC8ECEC66 0xE702B5BB */
	if (left == (0x89AEAF22 ^ cipherxor) && right == (0xA640F6FF ^ cipherxor))
	{
		stringDec(strings, 5);
		pPrintf((LPCSTR)strings);
		stringEnc(strings, 5);
	}
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);
	knp += 8;
	left ^= f(key, right, knp);
	knp += 8;
	right ^= f(key, left, knp);

	/* Left/right half swap, plus byte swap if little-endian */
#ifndef	WORDS_BIGENDIAN
	work[1] = byteswap32(left);
	work[0] = byteswap32(right);
#else
	work[0] = right;
	work[1] = left;
#endif
	permute_fp((char *) work, key, block);	/* Inverse initial permutation */
}

/* Permute inblock with perm */
static void permute_ip(char *inblock, DES_KEY * key, char *outblock)
{
	register char *ib, *ob;	/* ptr to input or output block */
	register char *p, *q;
	register int j;

	/* Clear output block */
	Bzero(outblock, 8);

	ib = inblock;
	for (j = 0; j < 16; j += 2, ib++) {	/* for each input nibble */
		ob = outblock;
		p = key->iperm[j][(*ib >> 4) & 0xf];
		q = key->iperm[j + 1][*ib & 0xf];
		/* and each output byte, OR the masks together */
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
	}
}

/* Permute inblock with perm */
static void permute_fp(char *inblock, DES_KEY * key, char *outblock)
{
	register char *ib, *ob;	/* ptr to input or output block */
	register char *p, *q;
	register int j;

	/* Clear output block */
	Bzero(outblock, 8);

	ib = inblock;
	for (j = 0; j < 16; j += 2, ib++) {	/* for each input nibble */
		ob = outblock;
		p = key->fperm[j][(*ib >> 4) & 0xf];
		q = key->fperm[j + 1][*ib & 0xf];
		/* and each output byte, OR the masks together */
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
		*ob++ |= *p++ | *q++;
	}
}

/* The nonlinear function f(r,k), the heart of DES */
static uint32_t f(DES_KEY * key, register uint32_t r, register char *subkey)
{
	register uint32_t *spp;
	register uint32_t rval, rt;
	register int er;

#ifdef	TRACE
	printf("f(%08lx, %02x %02x %02x %02x %02x %02x %02x %02x) = ",
	       r,
	       subkey[0], subkey[1], subkey[2],
	       subkey[3], subkey[4], subkey[5], subkey[6], subkey[7]);
#endif
	/* Run E(R) ^ K through the combined S & P boxes.
	 * This code takes advantage of a convenient regularity in
	 * E, namely that each group of 6 bits in E(R) feeding
	 * a single S-box is a contiguous segment of R.
	 */
	subkey += 7;

	/* Compute E(R) for each block of 6 bits, and run thru boxes */
	er = ((int) r << 1) | ((r & 0x80000000) ? 1 : 0);
	spp = &key->sp[7][0];
	rval = spp[(er ^ *subkey--) & 0x3f];
	spp -= 64;
	rt = (uint32_t) r >> 3;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rval |= spp[((int) rt ^ *subkey--) & 0x3f];
	spp -= 64;
	rt >>= 4;
	rt |= (r & 1) << 5;
	rval |= spp[((int) rt ^ *subkey) & 0x3f];
#ifdef	TRACE
	printf(" %08lx\n", rval);
#endif
	return rval;
}

/* initialize a perm array */
static void perminit_ip(DES_KEY * key)
{
	register int l, j, k;
	int i, m;

	stringDec((uint32_t *)ip, 16);

	/* Clear the permutation array */
	Bzero(key->iperm, 16 * 16 * 8);

	for (i = 0; i < 16; i++)	/* each input nibble position */
		for (j = 0; j < 16; j++)	/* each possible input nibble */
			for (k = 0; k < 64; k++) {	/* each output bit position */
				l = ip[k] - 1;	/* where does this bit come from */
				if ((l >> 2) != i)	/* does it come from input posn? */
					continue;	/* if not, bit k is 0    */
				if (!(j & nibblebit[l & 3]))
					continue;	/* any such bit in input? */
				m = k & 07;	/* which bit is this in the byte */
				key->iperm[i][j][k >> 3] |= bytebit[m];
			}

	stringEnc((uint32_t *)ip, 16);
}

static void perminit_fp(DES_KEY * key)
{
	register int l, j, k;
	int i, m;

	stringDec((uint32_t *)fp, 16);

	/* Clear the permutation array */
	Bzero(key->fperm, 16 * 16 * 8);

	for (i = 0; i < 16; i++)	/* each input nibble position */
		for (j = 0; j < 16; j++)	/* each possible input nibble */
			for (k = 0; k < 64; k++) {	/* each output bit position */
				l = fp[k] - 1;	/* where does this bit come from */
				if ((l >> 2) != i)	/* does it come from input posn? */
					continue;	/* if not, bit k is 0    */
				if (!(j & nibblebit[l & 3]))
					continue;	/* any such bit in input? */
				m = k & 07;	/* which bit is this in the byte */
				key->fperm[i][j][k >> 3] |= bytebit[m];
			}

	stringEnc((uint32_t *)fp, 16);
}

/* Initialize the lookup table for the combined S and P boxes */
static void spinit(DES_KEY * key)
{
	char pbox[32];
	int p, i, s, j, rowcol;
	uint32_t val;

	stringDec((uint32_t *)p32i, 8);

	for (s = 0; s < 8; s++) {
		stringDec((uint32_t *)(si[s]), 16);
	}

	/* Compute pbox, the inverse of p32i.
	 * This is easier to work with
	 */
	for (p = 0; p < 32; p++) {
		for (i = 0; i < 32; i++) {
			if (p32i[i] - 1 == p) {
				pbox[p] = i;
				break;
			}
		}
	}
	for (s = 0; s < 8; s++) {	/* For each S-box */
		for (i = 0; i < 64; i++) {	/* For each possible input */
			val = 0;
			/* The row number is formed from the first and last
			 * bits; the column number is from the middle 4
			 */
			rowcol =
			    (i & 32) | ((i & 1) ? 16 : 0) | ((i >> 1) &
							     0xf);
			for (j = 0; j < 4; j++) {	/* For each output bit */
				if (si[s][rowcol] & (8 >> j)) {
					val |=
					    1L << (31 - pbox[4 * s + j]);
				}
			}
			key->sp[s][i] = val;

#ifdef DEBUG
			printf("sp[%d][%2d] = %08lx\n", s, i,
			       key->sp[s][i]);
#endif
		}
	}

	stringEnc((uint32_t *)p32i, 8);

	for (s = 0; s < 8; s++) {
		stringEnc((uint32_t *)(si[s]), 16);
	}
}
