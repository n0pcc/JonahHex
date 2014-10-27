#ifndef IMPORT_H
#define IMPORT_H

#include <windows.h>
#include <winternl.h>
#include <stddef.h>

/* Begin typedefs ... */
typedef FARPROC (__stdcall *tdGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (__stdcall *tdLoadLibraryA)(LPCSTR lpLibFileName);
typedef int (__cdecl *tdprintf)(const char * format, ...);
typedef int (__cdecl *tdscanf)(const char * format, ...);
typedef void *(__cdecl *tdcalloc)(size_t num, size_t size);
typedef void *(__cdecl *tdmemset)(void *dest, int c, size_t count);
typedef void *(__cdecl *tdmemcpy)(void *dest, const void *src, size_t count);
typedef void (__cdecl *tdfree)(void *memblock);
typedef BOOL (WINAPI *tdVirtualProtect)(LPVOID lpAddress, DWORD dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef void (WINAPI *tdExitProcess)(UINT uExitCode);
/* End typedefs */

/* Begin function prototypes for import.c. */
HMODULE _GetModuleHandle(const wchar_t * lpModuleName);
FARPROC __stdcall _getProcAddress(HMODULE hModule, LPCSTR lpProcName);

int _wcscmp(const wchar_t *string1, const wchar_t *string2);
int _strcmp(const char *string1, const char *string2);
/* End function prototypes */

/* extern declarations of the function pointers of all functions being imported. */
extern tdGetProcAddress pGetProcAddress;
extern tdLoadLibraryA pLoadLibraryA;
extern tdprintf pPrintf;
extern tdscanf pScanf;
extern tdcalloc pCalloc;
extern tdmemset pMemset;
extern tdmemcpy pMemcpy;
extern tdfree pFree;
extern tdVirtualProtect pVirtualProtect;
extern tdExitProcess pExitProcess;

#endif
