#include <stdio.h>

#include "JonahHex.h"
#include "Import.h"
#include "des\des.h"

/* Authentication: DEAD696E18791211 => 0xDEAD in 0x1879 0x1 ! 0x1 */

/* .text section must be writable for code modifications. */
#pragma comment(linker,"/SECTION:.text,ERW") 

/* Begin TLS */
void NTAPI TlsCallback_0(PVOID handle, DWORD reason, PVOID resv);
void NTAPI TlsCallback_1(PVOID handle, DWORD reason, PVOID resv);

int AddressOfIndex[] = {1,0};
PIMAGE_TLS_CALLBACK AddressOfCallBacks[] = {&TlsCallback_0, 0, 0};

IMAGE_TLS_DIRECTORY _tls_used = {0, 0, (DWORD)AddressOfIndex, (DWORD)AddressOfCallBacks, 0, 0};

DWORD *pAddressOfCallBacks = (DWORD *)AddressOfCallBacks;
/* End TLS */

/* Module handles */
HMODULE self;
HMODULE ntdll;
HMODULE kernel32;
HMODULE msvcrt;

/* Function pointer */
tdGetProcAddress pGetProcAddress = _getProcAddress;
tdLoadLibraryA pLoadLibraryA;
tdprintf pPrintf;
tdscanf pScanf;
tdcalloc pCalloc;
tdmemset pMemset;
tdmemcpy pMemcpy;
tdfree pFree;
tdVirtualProtect pVirtualProtect;
tdExitProcess pExitProcess;

/* PE header structs of JonahHex (module self). */
PIMAGE_DOS_HEADER pDosHeader;
PIMAGE_NT_HEADERS pNtHeaders;
PIMAGE_OPTIONAL_HEADER pOptionalHeader;

DWORD AddressOfEntryPoint;

void main()
{
	char *keyword;
	char input[17];
	unsigned char plaintext[8] = {0};
	unsigned char ciphertext[8];
	uint32_t cipherxor = 0x41424344;
	DES_KEY key;

	uint32_t oldZoidberg = 0xFFFFFFFF, Zoidberg = 12;
	uint32_t strings[20];

	uint8_t *ccLoopPosition, *ccLoopEnd, ccCount = 0;

	while (1)
	{
		/* 
		 * *pAddressOfCallBacks = 0;																// case 12
		 * 
		 * if (pPrintf == NULL)																		// case 12
		 * 		return;																				// case 0
		 * 
		 * if (pScanf == NULL)																		// case 11
		 * 		return;																				// case 0
		 * 
		 * if (pMemset == NULL)																		// case 18
		 * 		return;																				// case 0
		 * 
		 * if (pMemcpy == NULL)																		// case 5
		 * 		return;																				// case 0
		 * 
		 * if (pFree == NULL)																		// case 7
		 * 		return;																				// case 0
		 * 
		 * 
		 * keyword = (char *)pCalloc(8, 1);															// case 14
		 * 
		 * if (keyword == NULL)																		// case 14
		 * 		return;																				// case 0
		 * 
		 * 																							// Setting up the string: case 12, 11, 18, 5, 7
		 * pPrintf("Batcommunicator\n\nAuthenticate: ");											// Calls string enc/dec, pPrintf: case 16
		 * 
		 * 																							// Setting up the string: case 16
		 * pScanf("%16s", &input);																	// Calls string enc/dec, pScanf: case 15
		 * 
		 * if (hexStr2Bytes(input, plaintext, 16) == 0)												// case 6
		 * 		return;																				// case 0
		 * 
		 * ccLoopPosition = (uint8_t *)self + 0x1000;												// case 8
		 * ccLoopEnd = (uint8_t *)self + 0x4000;													// case 8
		 * 
		 * while (ccLoopEnd - ccLoopPosition + 0x500 > 0x500)										// case 9
		 * {
		 * 		if (!(*ccLoopPosition ^ 0xC2 ^ 0x11 ^ 0x1F))										// case 10
		 * 			ccCount++;																		// case 10
		 * 
		 * 		ccLoopPosition++;																	// case 10
		 * 
		 * 		if (ccCount % 22 == 0)																// default
		 * 			ccCount *= ccCount + 42;														// default
		 * }
		 * 
		 * keyword[0] = ccCount;																	// case 0x500
		 * keyword[1] = ccCount;
		 * keyword[2] = ccCount;
		 * keyword[3] = ccCount;
		 * keyword[4] = ccCount;
		 * keyword[5] = ccCount;
		 * keyword[6] = ccCount;
		 * keyword[7] = ccCount;
		 * 
		 * pMemcpy(ciphertext, plaintext, 8);														// case 4
		 * *(uint32_t *)keyword ^= cipherxor;														// case 4
		 * 
		 * _mcrypt_set_key(&key, keyword, 8);														// case 19
		 * 
		 * _mcrypt_encrypt(&key, ciphertext);														// case 13
		 * 
		 * if ((*(DWORD *)ciphertext == (0xC2E774E2 ^ cipherxor)) 									// if else is case 17
		 *     && (*(DWORD *)(ciphertext+4) == (0xAB327141 ^ cipherxor)))
		 * {
		 * 		Zoidberg = 1;
		 * }
		 * else
		 * {
		 * 		pFree(keyword);
		 * 		Zoidberg = 0;
		 * }
		 * 
		 * 																							// Is in des.c as a tip to calculate
		 * pPrintf("Communicationflag: ");															// the DES backwards after 2 rounds.
		 * 
		 * ccLoopPosition = plaintext;																// case 1
		 * ccLoopEnd = plaintext + 8;																// case 1
		 * 
		 * while (ccLoopEnd - ccLoopPositioin + 0x100 > 0x100)										// case 2
		 * {
		 * 																							// Setting up the string: case 17
		 * 		pPrintf("%02X", *ccLoopPosition);													// Whole loop body is case 3
		 * 
		 * 		ccLoopPosition++;	
		 * }
		 * 
		 * ccLoopPosition = keyword;																// case 20
		 * ccLoopEnd = keyword + 8;																	// case 20
		 * 
		 * while (ccLoopEnd - ccLoopPositioin + 0x100 > 0x100)										// case 21
		 * {
		 * 																							// Setting up the string: case 17
		 * 		pPrintf("%02X", *ccLoopPosition);													// Whole loop body is case 22
		 * 
		 * 		ccLoopPosition++;	
		 * }
		 * 
		 * 																							// Setting up the string: case 0x100
		 * pPrintf("\n\nError: No Connectivity...");												// Calls string enc/dec, pPrintf: case 0x100
		 * 
		 * pFree(keyword);																			// case 0x100
		 * 
		 * return;																					// case 0
		 * 
		 */

		/* 12->11->18->5->7->14->16->15->6->(8->9->10)->4->19->13->17->(1->2->3)->(20->21->22) */
		switch (Zoidberg)
		{
			case 0:
				return;
			case 1:
				/* Next: 2 */
				/* Loop to print the entered plaintext as hex. */
				strings[1] = 0xFFFFFFFF;
				ccLoopPosition = plaintext;
				ccLoopEnd = plaintext + 8;

				oldZoidberg = 1863695;
				Zoidberg++;
				break;
			case 2:
				/* Next: (default -> 3) or 0x100 */
				Zoidberg = (DWORD)(ccLoopEnd - ccLoopPosition + 0x100);
				break;
			case 3:
				/* Next: 2 */
				/* "%02X" */
				stringDec(strings, 2);
				pPrintf((LPCSTR)strings, *ccLoopPosition);
				stringEnc(strings, 2);

				ccLoopPosition++;

				Zoidberg--;
				break;
			case 4:
				/* Next: 19 */
				pMemcpy(ciphertext, plaintext, 8);
				*(uint32_t *)keyword ^= cipherxor;

				Zoidberg = 76072;
				Zoidberg %= 101;
				break;
			case 5:
				/* Next: 7 */
				strings[2] = 0xD6FEE291;

				oldZoidberg = 315834;
				Zoidberg = (DWORD)pMemcpy;
				break;
			case 6:
				/* Next: 8 */
				oldZoidberg = 384635;
				Zoidberg = hexStr2Bytes(input, plaintext, 16);
				break;
			case 7:
				/* Next: 14 */
				strings[3] = 0xF0B5978C;

				oldZoidberg = 384635;
				Zoidberg = (DWORD)pFree;
				break;
			case 8:
				/* Next: 9 */
				/* 
				 * Loop through all bytes of the text section and look for int 3s.
				 * Loop start/end condition.
				 */
				ccLoopPosition = (uint8_t *)self + 0x1000;
				ccLoopEnd = (uint8_t *)self + 0x4000;

				oldZoidberg = 46915;
				Zoidberg++;
				break;
			case 9:
				/* Next: (default -> 10) or 0x500 */
				/* Checking if the end condition is reached. */
				Zoidberg = (DWORD)(ccLoopEnd - ccLoopPosition + 0x500);
				break;
			case 10:
				/* Next: 9 */
				/* Loop body. */
				if (!(*ccLoopPosition ^ 0xC2 ^ 0x11 ^ 0x1F))
					ccCount++;

				ccLoopPosition++;

				Zoidberg--;
				break;
			case 11:
				/* Next: 18 */
				strings[0] = 0xFB9FE1F0;
				strings[6] = 0xA4F996AB;
				strings[7] = 0xDFC59AFF;

				oldZoidberg = 275194;
				Zoidberg = (DWORD)pScanf;
				break;
			case 12:
				/* Next: 11 */
				/* 
				 * Empty the TLS callback pointer list.
				 * Start checking if the import of the functions succeeded.
				 */
				*pAddressOfCallBacks = 0;
				strings[4] = 0x8682DAE3;
				strings[5] = 0x97F3C3D0;

				oldZoidberg = 287695;
				Zoidberg = (DWORD)pPrintf;
				break;
			case 13:
				/* Next: 17 */
				_mcrypt_encrypt(&key, ciphertext);

				Zoidberg = 996180;
				Zoidberg %= 101;
				break;
			case 14:
				/* Next: 16 */
				/* Allocate 8 bytes for the DES key. */
				keyword = (char *)pCalloc(8, 1);

				oldZoidberg = 1694850;
				Zoidberg = (DWORD)keyword;
				break;
			case 15:
				/* Next: 6 */
				/* "%16s" */
				stringDec(strings, 2);
				pScanf((LPCSTR)strings, &input);
				stringEnc(strings, 2);

				Zoidberg = 68967;
				Zoidberg %= 127;
				break;
			case 16:
				/* Next: 15 */
				/* "Enter the secret:\n" */
				stringDec(strings, 8);
				pPrintf((LPCSTR)strings);
				stringEnc(strings, 8);
				strings[0] = 0xC9CEDA8C;
				strings[1] = 0xFFFFFFFF;

				Zoidberg = 27083;
				Zoidberg %= 101;
				break;
			case 17:
				/* Next: 1 or 0 */
				/* 0x83A537A6 0xEA703205 */
				if ((*(DWORD *)ciphertext == (0xC2E774E2 ^ cipherxor)) 
					&& (*(DWORD *)(ciphertext+4) == (0xAB327141 ^ cipherxor)))
				{
					strings[0] = 0xCDCFDAA7;
					Zoidberg = 1;
				}
				else
				{
					pFree(keyword);
					Zoidberg = 0;
				}
				break;
			case 18:
				/* Next: 5 */
				strings[1] = 0x938FFEA3;

				oldZoidberg = 165736;
				Zoidberg = (DWORD)pMemset;
				break;
			case 19:
				/* Next: 13 */
				_mcrypt_set_key(&key, keyword, 8);

				Zoidberg = 107455;
				Zoidberg %= 127;
				break;
			case 20:
				/* Next: 21 */
				/* Loop to print the constructed keyword as hex. */
				ccLoopPosition = keyword;
				ccLoopEnd = keyword + 8;

				oldZoidberg = 1519744;
				Zoidberg++;
				break;
			case 21:
				/* Next: (default -> 22) or 0x100 */
				Zoidberg = (DWORD)(ccLoopEnd - ccLoopPosition + 0x100);
				break;
			case 22:
				/* Next: 21 */
				/* "%02X" */
				stringDec(strings, 2);
				pPrintf((LPCSTR)strings, *ccLoopPosition);
				stringEnc(strings, 2);

				ccLoopPosition++;

				Zoidberg--;
				break;
			case 0x500:
				/* Next: 4 */
				/* int 3 search loop finished case. */
				keyword[0] = ccCount;
				keyword[1] = ccCount;
				keyword[2] = ccCount;
				keyword[3] = ccCount;
				keyword[4] = ccCount;
				keyword[5] = ccCount;
				keyword[6] = ccCount;
				keyword[7] = ccCount;

				Zoidberg = oldZoidberg % 3127;
				Zoidberg -= 6;
				break;
			case 0x100:
				/* Next: 20 or 0 */
				/* Print loop finished case. */
				if (oldZoidberg == 1863695)
				{
					Zoidberg = oldZoidberg % 3127;
					Zoidberg += 17;
				}
				else
				{
					strings[10] = 0xA8DCFDC1;
					strings[11] = 0xB3EDD6F7;
					strings[12] = 0xCDC182A4;
					strings[13] = 0x84A28FA2;
					strings[14] = 0xCCEACDCC;
					strings[15] = 0xA5B889A8;
					strings[16] = 0xD1D1D1FF;

					stringDec(strings + 10, 7);
					pPrintf((LPCSTR)(strings + 10), *ccLoopPosition);
					stringEnc(strings + 10, 7);

					pFree(keyword);
					Zoidberg = 0;
				}
				
				break;
			default:
				/* Used for NULL check of pointers and looping. */
				if (oldZoidberg == 46915 && ccCount % 22 == 0)
					ccCount *= ccCount + 42;

				Zoidberg = oldZoidberg % 3127;
				break;
		}
	}
}

void NTAPI TlsCallback_0(PVOID handle, DWORD reason, PVOID resv)
{
	uint32_t *jmpAddress, *Zoidberg;
	uint32_t strings[20];

	strings[3] = 4;
	strings[9] = 0;
	strings[18] = 5;
	strings[2] = 0xBDA0FEA1;

	Zoidberg = strings + 13;

	strings[16] = 56;
	strings[13] = 12;
	strings[6] = 0xFFFFFFFF;

	while (1)
	{
		/*
		 * pAddressOfCallBacks++;													// case 0
		 * *pAddressOfCallBacks = (DWORD)&TlsCallback_1;							// case 5
		 * pAddressOfCallBacks--;													// case 8
		 * 
		 * self = _GetModuleHandle(NULL);											// case 12
		 * 
		 * 																			// Setting up the string: case 3, 0, before while
		 * kernel32 = _GetModuleHandle(L"kernel32.dll");							// Calls string enc/dec, _GetModuleHandle: case 10
		 * 
		 * // Decrypt 3 jumps in TlsCallback_1
		 * jmpAddress = (uint32_t *)self;											// case 2
		 * 																			// Setting up the offset (strings[7]) and decrypting it: case 4, 8
		 * jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[7]);		// case 7
		 * 																			// Setting up the value (0x8) to xor: case 2
		 * *jmpAddress ^= strings[19];												// case 7
		 * 
		 * 																			// Setting up the offset (strings[10]): case 10
		 * jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[10]);	// case 9
		 * 																			// Setting up the value (0x40) to xor: case 6
		 * *jmpAddress ^= strings[19];												// case 1
		 * 
		 * 																			// Setting up the offset (strings[9]): case 10
		 * jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[9]);		// case 11
		 * 																			// Setting up the value (0x200) to xor: case 1
		 * *jmpAddress ^= strings[19];												// case 11
		 * 
		 * pDosHeader = (PIMAGE_DOS_HEADER)self;									// default
		 * 
		 * return;																	// default
		 */

		/* 12->3->0->10->2->4->5->8->7->6->9->1->11->default */
		switch (*Zoidberg)
		{
			case 0:
				/* Next: 10 */
				strings[0] = 0x9BD3D6CE;
				strings[1] = 0xCEFED3BD;
				pAddressOfCallBacks++;
				strings[3] = 0xA1D1A09B;
				strings[8] = 0xFFFFFFFF;

				strings[14] = 3;
				*Zoidberg += 10;
				strings[15] = 3;
				break;
			case 1:
				/* Next: 11 */
				*jmpAddress ^= strings[19];												// XOR of second jump: 0x40
				strings[19] <<= strings[13];

				*Zoidberg *= 11;
				break;
			case 2:
				/* Next: 4 */
				strings[19] = 1;
				strings[19] <<= strings[13];
				jmpAddress = (uint32_t *)self;

				(*Zoidberg)++;
				(*Zoidberg)++;
				(*Zoidberg)++;
				Zoidberg = strings + 14;
				break;
			case 3:
				/* Next: 0 */
				strings[4] = 0x9B93D193;
				strings[5] = 0x93FF93FF;

				Zoidberg = strings + 9;
				break;
			case 4:
				/* Next: 5 */
				strings[7] = 0xFCFFFFE8;												// Offset to first jump has to be adjusted in code
																						// or in the binary after code changes: stringDec(0x00001703, 1);

				(*Zoidberg)++;
				*Zoidberg += 2;
				(*Zoidberg)++;
				Zoidberg = strings + 15;
				break;
			case 5:
				/* Next: 8 */
				*pAddressOfCallBacks = (DWORD)&TlsCallback_1;

				Zoidberg = strings + 14;
				break;
			case 6:
				/* Next: 9 */
				strings[19] <<= strings[13];

				Zoidberg = strings + 3;
				break;
			case 7:
				/* Next: 6 */
				jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[7]);
				*jmpAddress ^= strings[19];												// XOR of first jump: 0x8

				(*Zoidberg)--;
				break;
			case 8:
				/* Next: 7 */
				stringEnc(strings + 7, 1);
				pAddressOfCallBacks--;

				(*Zoidberg)--;
				strings[3] = 9;
				break;
			case 9:
				/* Next: 1 */
				jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[10]);

				*Zoidberg = 1;
				break;
			case 10:
				/* Next: 2 */
				stringDec(strings, 7);
				strings[10] = 0x00000009;												// Offset to second jump has to be adjusted in code
																						// or in the binary after code changes: 0x0000170C
				kernel32 = _GetModuleHandle((const wchar_t *)strings);
				stringEnc(strings, 7);
				strings[9] = 0x0000099A;												// Offset to third jump has to be adjusted in code
																						// or in the binary after code changes: 0x000020A6

				Zoidberg = strings + 15;
				(*Zoidberg)--;
				strings[14]++;
				break;
			case 11:
				/* Next: default */
				jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + strings[9]);
				*jmpAddress ^= strings[19];												// XOR of third jump: 0x200

				(*Zoidberg)++;
				break;
			case 12:
				/* Next: 3 */
				self = _GetModuleHandle(NULL);

				(*Zoidberg) /= 4;
				break;
			default:
				pDosHeader = (PIMAGE_DOS_HEADER)self;
				return;
		}
	}
}

void NTAPI TlsCallback_1(PVOID handle, DWORD reason, PVOID resv)
{
	uint32_t *jmpAddress, Zoidberg;
	uint32_t strings[20];

	char *DbgBreakPoint;
	char *DbgUiRemoteBreakin;
	DWORD dwOldProtect;

	Zoidberg = 12126;
	Zoidberg %= 83;

	while (1)
	{
		/* 
		 * 																												// Setting up the string: case 8
		 * pGetProcAddress = (FARPROC (__stdcall*)(HMODULE, LPCSTR))pGetProcAddress(kernel32, "GetProcAddress");		// Calls string enc/dec, pGetProcAddress: case 20
		 * 
		 * 																												// Setting up the string: case 1
		 * pLoadLibraryA = (HMODULE (__stdcall *)(LPCSTR))pGetProcAddress(kernel32, "LoadLibraryA");					// Calls: case 23
		 * 
		 * 																												// Setting up the string: case 14
		 * msvcrt = pLoadLibraryA("msvcrt.dll");																		// Calls: case 26
		 * 
		 * 																												// Setting up the string: case 31
		 * pScanf = (int (__cdecl *)(const char *, ...))pGetProcAddress(msvcrt, "scanf");								// Calls: case 17
		 * 
		 * 																												// Setting up the string: case 13
		 * pPrintf = (int (__cdecl *)(const char *, ...))pGetProcAddress(msvcrt, "printf");								// Calls: case 19
		 * 
		 * 																												// Setting up the string: case 24
		 * pCalloc = (void *(__cdecl *)(size_t, size_t))pGetProcAddress(msvcrt, "calloc");								// Calls: case 29
		 * 
		 * 																												// Setting up the string: case 22
		 * pMemset = (void *(__cdecl *)(void *, int, size_t))pGetProcAddress(msvcrt, "memset");							// Calls: case 18
		 * 
		 * 																												// Setting up the string: case 6
		 * pMemcpy = (void *(__cdecl *)(void *, const void *, size_t))pGetProcAddress(msvcrt, "memcpy");				// Calls: case 16
		 * 
		 * 																												// Setting up the string: case 10
		 * pFree = (void (__cdecl *)(void *))pGetProcAddress(msvcrt, "free");											// Calls: case 7
		 * 
		 * pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)self + pDosHeader->e_lfanew);										// case 7
		 * 
		 * 																												// Setting up the string: case 28
		 * pVirtualProtect = (BOOL (WINAPI *)(LPVOID, DWORD, DWORD, PDWORD))pGetProcAddress(kernel32, "VirtualProtect");// Calls: case 5
		 *
		 * 																												// Setting up the string: case 9
		 * pExitProcess = (void (WINAPI *)(UINT))pGetProcAddress(kernel32, "ExitProcess");								// Calls: case 11
		 * 
		 * 																												// Setting up the string: case 27
		 * ntdll = _GetModuleHandle(L"ntdll.dll");																		// Calls: case 0
		 * 
		 * 																												// Setting up the string: case 4
		 * DbgBreakPoint = (char *)pGetProcAddress(ntdll, "DbgBreakPoint");												// Calls: case 30
		 * 
		 * // Overwriting the int3 in DbgBreakPoint() with ret 
		 * if (pVirtualProtect((LPVOID)DbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))						// case 30
		 * {
		 * 		pOptionalHeader = &pNtHeaders->OptionalHeader;															// case 30
		 *		*DbgBreakPoint = 0xC3;																					// case 30
		 * }
		 * 
		 * 																												// Setting up the string: case 25
		 * DbgUiRemoteBreakin = (char *)pGetProcAddress(ntdll, "DbgUiRemoteBreakin");									// Calls: case 21
		 * 
		 * // Overwriting the int3 in DbgUiRemoteBreakin() with ret 
		 * if (pVirtualProtect((LPVOID)DbgUiRemoteBreakin, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))					// case 21
		 * {
		 * 		AddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;												// case 21
		 *		*DbgUiRemoteBreakin = 0xC3;																				// case 21
		 * }
		 * 
		 * // Decrypt 2 jumps in main()
		 * jmpAddress = (uint32_t *)self;																				// case 12
		 * jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + 0x0000217C);											// case 12
		 * *jmpAddress ^= 0x2fe095ad;																					// case 3
		 * 
		 * jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + 0x0000067C);											// case 15
		 * *jmpAddress ^= 0x1660d216;																					// case 15
		 * 
		 * main();																										// case 2
		 * 
		 * pExitProcess(0)																								// default
		 */

		/* 
		 * 8->20->1->23->14->26->13->31->17->19->12->24->29->22->6->18
		 * ->16->3->10->27->0->7->28->5->4->30->25->21->9->11->15->2->default
		 */
		switch (Zoidberg)
		{
			case 0:
				/* Next: 7 */
				stringDec(strings + 10, 5);
				ntdll = _GetModuleHandle((const wchar_t *)(strings + 10));
				stringEnc(strings + 10, 5);
				
				Zoidberg = 250103;
				Zoidberg %= 29;
				break;
			case 1:
				/* Next: 23 */
				/* "LoadLibraryA" */
				strings[3] = 0x969DB88B;
				strings[4] = 0xEFF7F2F4;
				strings[5] = 0x868D9EBE;
				strings[6] = 0xFFFFFFFF;
				
				Zoidberg = 25507;
				Zoidberg %= 277;
				break;
			case 2:
				/* Next: default */
				main();

				Zoidberg = 7079;
				Zoidberg %= 71;
				break;
			case 3:
				/* Next: 10 */
				*jmpAddress ^= 0x2fe095ad;												// XOR of first jump
				
				Zoidberg = 76252;
				Zoidberg %= 131;
				break;
			case 4:
				/* Next: 30 */
				/* "DbgBreakPoint" */
				strings[0] = 0xAD81B9C7;
				strings[1] = 0x85CAE3FD;
				strings[2] = 0x96E4AF91;
				strings[3] = 0xFFFF8BFF;
				
				Zoidberg *= 218616;
				Zoidberg /= 2;
				Zoidberg %= 227;
				break;
			case 5:
				/* Next: 4 */
				stringDec(strings, 4);
				pVirtualProtect = (BOOL (WINAPI *)(LPVOID, DWORD, DWORD, PDWORD))pGetProcAddress(kernel32, (LPCSTR)strings);
				stringEnc(strings, 4);
				
				Zoidberg = 71492;
				Zoidberg %= 1117;
				break;
			case 6:
				/* Next: 18 */
				/* "memcpy" */
				strings[3] = 0xEBEA929C;
				strings[4] = 0xFF868FFF;
				
				Zoidberg = 364279;
				Zoidberg %= 647;
				break;
			case 7:
				/* Next: 28 */
				stringDec(strings + 15, 2);
				pFree = (void (__cdecl *)(void *))pGetProcAddress(msvcrt, (LPCSTR)(strings + 15));
				pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)self + pDosHeader->e_lfanew);
				stringEnc(strings + 15, 2);
				
				Zoidberg = 369751;
				Zoidberg %= 491;
				break;
			case 8:
				/* Next: 20 */
				/* "GetProcAddress" */
				strings[0] = 0x808DF8DB;
				strings[1] = 0x8BF4E8BF;
				strings[2] = 0xFEE89B9A;
				strings[3] = 0xFF8C8CFF;
				
				Zoidberg = 2223;
				Zoidberg = (uint8_t)Zoidberg;
				Zoidberg %= 31;
				break;
			case 9:
				/* Next: 11 */
				/* "ExitProcess" */
				strings[1] = 0x81D7AA97;
				strings[2] = 0xE3E8AFEF;
				strings[3] = 0x8C8C9AFF;
				
				Zoidberg = 124067;
				Zoidberg %= 1723;
				break;
			case 10:
				/* Next: 27 */
				/* "free" */
				strings[15] = 0x9A8D999A;
				strings[16] = 0xFFFFFFFF;
				
				Zoidberg = 180085;
				Zoidberg %= 197;
				break;
			case 11:
				/* Next: 15 */
				stringDec(strings + 1, 3);
				pExitProcess = (void (WINAPI *)(UINT))pGetProcAddress(kernel32, (LPCSTR)(strings + 1));
				stringEnc(strings + 1, 3);
				
				Zoidberg = 98071;
				Zoidberg %= 103;
				break;
			case 12:
				/* Next: 24 */
				jmpAddress = (uint32_t *)self;
				jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + 0x000021AC);	// Offset to first jump has to be adjusted in code
																						// or in the binary after code changes: 0x000021AC
				
				Zoidberg = 52782;
				Zoidberg %= 977;
				break;
			case 13:
				/* Next: 31 */
				/* "printf" */
				strings[0] = 0xF0F98F91;
				strings[1] = 0xFF998BFF;
				
				Zoidberg = 1922452;
				Zoidberg %= 211;
				break;
			case 14:
				/* Next: 26 */
				/* "msvcrt.dll" */
				strings[10] = 0x91FEF6DE;
				strings[11] = 0xBDE78D9B;
				strings[12] = 0xFF9393FF;

				Zoidberg = 827721;
				Zoidberg %= 149;
				break;
			case 15:
				/* Next: 2 */
				jmpAddress = (uint32_t *)((unsigned char *)jmpAddress + 0x00000684);	// Offset to second jump has to be adjusted in code
																						// or in the binary after code changes: 0x00002830
				*jmpAddress ^= 0x1660d216;												// XOR of second jump

				Zoidberg = 83034;
				Zoidberg %= 97;
				break;
			case 16:
				/* Next: 3 */
				stringDec(strings + 3, 2);
				pMemcpy = (void *(__cdecl *)(void *, const void *, size_t))pGetProcAddress(msvcrt, (LPCSTR)(strings + 3));
				stringEnc(strings + 3, 2);
				
				Zoidberg = 309084;
				Zoidberg %= 269;
				break;
			case 17:
				/* Next: 19 */
				stringDec(strings + 2, 2);
				pScanf = (int (__cdecl *)(const char *, ...))pGetProcAddress(msvcrt, (LPCSTR)(strings + 2));
				stringEnc(strings + 2, 2);
				
				Zoidberg = 268282;
				Zoidberg %= 727;
				break;
			case 18:
				/* Next: 16 */
				stringDec(strings, 2);
				pMemset = (void *(__cdecl *)(void *, int, size_t))pGetProcAddress(msvcrt, (LPCSTR)strings);
				stringEnc(strings, 2);
				
				Zoidberg = 31627;
				Zoidberg %= 257;
				break;
			case 19:
				/* Next: 12 */
				stringDec(strings, 2);
				pPrintf = (int (__cdecl *)(const char *, ...))pGetProcAddress(msvcrt, (LPCSTR)strings);
				stringEnc(strings, 2);
				
				Zoidberg = 48844;
				Zoidberg %= 109;
				break;
			case 20:
				/* Next: 1 */
				stringDec(strings, 4);
				pGetProcAddress = (FARPROC (__stdcall*)(HMODULE, LPCSTR))pGetProcAddress(kernel32, (LPCSTR)strings);
				stringEnc(strings, 4);
				
				Zoidberg %= 19;
				break;
			case 21:
				/* Next: 9 */
				stringDec(strings, 5);
				DbgUiRemoteBreakin = (char *)pGetProcAddress(ntdll, (LPCSTR)strings);
				stringEnc(strings, 5);

				if (pVirtualProtect((LPVOID)DbgUiRemoteBreakin, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					AddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;
					*DbgUiRemoteBreakin = 0xC3;
				}
				
				Zoidberg = 497383;
				Zoidberg %= 577;
				break;
			case 22:
				/* Next: 6 */
				/* "memset" */
				strings[0] = 0xE6FF928C;
				strings[1] = 0xFF8B9AFF;
				
				Zoidberg = 25794;
				Zoidberg %= 307;
				break;
			case 23:
				/* Next: 14 */
				stringDec(strings + 3, 4);
				pLoadLibraryA = (HMODULE (__stdcall *)(LPCSTR))pGetProcAddress(kernel32, (LPCSTR)(strings + 3));
				stringEnc(strings + 3, 4);
				
				Zoidberg = 441242;
				Zoidberg %= 443;
				break;
			case 24:
				/* Next: 29 */
				/* "calloc" */
				strings[8] = 0xF0F19C93;
				strings[9] = 0xFF9C90FF;
				
				Zoidberg = 244120;
				Zoidberg = (uint8_t)Zoidberg;
				Zoidberg %= 41;
				break;
			case 25:
				/* Next: 21 */
				/* "DbgUiRemoteBreakin" */
				strings[0] = 0xCEB9BFC9;
				strings[1] = 0x9CA9DBFB;
				strings[2] = 0x96F9FBB2;
				strings[3] = 0xF0F38D94;
				strings[4] = 0xFF9196FF;
				
				Zoidberg = 34477;
				Zoidberg %= 59;
				break;
			case 26:
				/* Next: 13 */
				stringDec(strings + 10, 3);
				msvcrt = pLoadLibraryA((LPCSTR)(strings + 10));
				stringEnc(strings + 10, 3);
				
				Zoidberg = 566967;
				Zoidberg %= 67;
				break;
			case 27:
				/* Next: 0 */
				/* L"ntdll.dll" */
				strings[10] = 0xE7F7D3F7;
				strings[11] = 0xF793F7BD;
				strings[12] = 0xBD9B9393;
				strings[13] = 0x93939BFF;
				strings[14] = 0xFFFF93FF;
				
				Zoidberg = 141474;
				Zoidberg %= 73;
				break;
			case 28:
				/* Next: 5 */
				/* "VirtualProtect" */
				strings[0] = 0x9E86F9EB;
				strings[1] = 0x9FECEFAF;
				strings[2] = 0xFFF38D9A;
				strings[3] = 0xFF8B9CFF;
				
				Zoidberg = 99;
				Zoidberg += 17000;
				Zoidberg %= 37;
				break;
			case 29:
				/* Next: 22 */
				stringDec(strings + 8, 2);
				pCalloc = (void *(__cdecl *)(size_t, size_t))pGetProcAddress(msvcrt, (LPCSTR)(strings + 8));
				stringEnc(strings + 8, 2);
				
				Zoidberg = 46573;
				Zoidberg %= 59;
				break;
			case 30:
				/* Next: 25 */
				stringDec(strings, 4);
				DbgBreakPoint = (char *)pGetProcAddress(ntdll, (LPCSTR)strings);
				stringEnc(strings, 4);

				if (pVirtualProtect((LPVOID)DbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					pOptionalHeader = &pNtHeaders->OptionalHeader;
					*DbgBreakPoint = 0xC3;
				}
				
				Zoidberg = 31630;
				Zoidberg %= 43;
				break;
			case 31:
				/* Next: 17 */
				/* "scanf" */
				strings[2] = 0x9EFA8C91;
				strings[3] = 0xFFFF99FF;
				
				Zoidberg = 13610;
				Zoidberg %= 23;
				break;
			default:
				pExitProcess(0);
		}
	}
}

void stringEnc(uint32_t *string, int length)
{
	uint32_t tmp;
	int i;

	tmp = ~string[length - 1];
	tmp = (tmp << 8) | (tmp >> (32 - 8));
	string[length - 1] = tmp;

	for (i = length - 2; i >= 0; i--)
	{
		tmp = string[i] ^ string[i + 1];
		tmp = (tmp << 8) | (tmp >> (32 - 8));
		string[i] = tmp;
	}
}

void stringDec(uint32_t *string, int length)
{
	uint32_t tmp;
	int i;

	for (i = 0; i < length - 1; i++)
	{
		tmp = string[i];
		tmp = (tmp >> 8) | (tmp << (32 - 8));
		string[i] = tmp ^ string[i + 1];
	}

	tmp = ~string[length - 1];
	tmp = (tmp >> 8) | (tmp << (32 - 8));
	string[length - 1] = tmp;
}

DWORD hexStr2Bytes(char *input, unsigned char *output, int length)
{
	int i;

	for (i = 0; i < length; i++)
	{
		if ('0' <= input[i] && input[i] <= '9')
			output[i / 2] |= (input[i] - '0') << (4 * ((i + 1) % 2));
		else if ('a' <= input[i] && input[i] <= 'f')
			output[i / 2] |= (input[i] - 'a' + 10) << (4 * ((i + 1) % 2));
		else if ('A' <= input[i] && input[i] <= 'F')
			output[i / 2] |= (input[i] - 'A' + 10) << (4 * ((i + 1) % 2));
		else
			return 0;
	}

	return 8;
}