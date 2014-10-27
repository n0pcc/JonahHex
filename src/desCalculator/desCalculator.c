#include <stdio.h>
#include <stdint.h>
#include "des.h"

int main()
{
	char *keyword;
	unsigned char plaintext[16];
	unsigned char ciphertext[16];
	int j;
	DES_KEY key;
	uint32_t AddressOfEntryPoint = 0x00002140;

	keyword = (char *)calloc(8, 1);
	if (keyword == NULL)
		return -1;

	for (j = 0; j < 8; j++) {
		// The key goes here
		keyword[j] = '\x7f';
	}

	*(uint32_t *)keyword ^= 0x41424344;
	*((uint32_t *)keyword + 1) ^= AddressOfEntryPoint;

	/* Authentication: DEAD696E18791211 => 0xDEAD in 0x1879 0x1 ! 0x1 */
	plaintext[0] = '\xDE';
	plaintext[1] = '\xAD';
	plaintext[2] = '\x69';
	plaintext[3] = '\x6E';
	plaintext[4] = '\x18';
	plaintext[5] = '\x79';
	plaintext[6] = '\x12';
	plaintext[7] = '\x11';

	memcpy(ciphertext, plaintext, 8);

	_mcrypt_set_key(&key, (void *) keyword, 8);
	free(keyword);

	_mcrypt_encrypt(&key, (void *) ciphertext);


	printf("des_output_value = [0x%02X",ciphertext[3]);
	printf("%02X",ciphertext[2]);
	printf("%02X",ciphertext[1]);
	printf("%02X, ",ciphertext[0]);
	printf("0x%02X",ciphertext[7]);
	printf("%02X",ciphertext[6]);
	printf("%02X",ciphertext[5]);
	printf("%02X]",ciphertext[4]);

	return 0;
}