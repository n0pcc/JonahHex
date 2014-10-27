#ifndef JONAHHEX_H
#define JONAHHEX_H

#include <windows.h>
#include <stdint.h>

void stringEnc(uint32_t *string, int length);
void stringDec(uint32_t *string, int length);

DWORD hexStr2Bytes(char *input, unsigned char *output, int length);

extern DWORD AddressOfEntryPoint;

#endif