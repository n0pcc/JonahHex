#include "Import.h"

PPEB pPeb = NULL;

HMODULE _GetModuleHandle(const wchar_t * lpModuleName)
{
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = NULL;
	PLIST_ENTRY pFirstModule = NULL;
	PLIST_ENTRY pCurrentModule = NULL;

	__asm
	{
		mov eax, fs:[0x30];
		mov [pPeb], eax;
	}

	pFirstModule = &(pPeb->Ldr->InMemoryOrderModuleList);

	for (pCurrentModule = pFirstModule->Flink; pCurrentModule != pFirstModule; pCurrentModule = pCurrentModule->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentModule;

		if (lpModuleName == NULL)
			return (HMODULE)pLdrDataTableEntry->Reserved2[0];

		if (!_wcsicmp(lpModuleName, pLdrDataTableEntry->FullDllName.Buffer))
			return (HMODULE)pLdrDataTableEntry->Reserved2[0];
	}

	return NULL;
}

FARPROC __stdcall _getProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	DWORD i;
	PBYTE pbBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pbBase + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pbBase + 
		pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD *dwAddressOfFunctions = (DWORD *)(pbBase + pExportDirectory->AddressOfFunctions);
	DWORD *dwAddressOfNames = (DWORD *)(pbBase + pExportDirectory->AddressOfNames);
	WORD *wAddressOfNameOrdinals = (WORD *)(pbBase + pExportDirectory->AddressOfNameOrdinals);

	for (i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		if (!_strcmp(lpProcName, (const char *)(pbBase + dwAddressOfNames[i])))
		{
			return (FARPROC)(pbBase + dwAddressOfFunctions[wAddressOfNameOrdinals[i]]);
		}
	}

	return NULL;
}

int _strcmp(const char *string1, const char *string2)
{
	int result = *string1++ - *string2++;

	while (!result && *string1)
		result = *string1++ - *string2++;

	if (result < 0)
		return -1;
	if (result > 0)
		return 1;

	return 0;
}

int _wcsicmp(const wchar_t *string1, const wchar_t *string2)
{
	int result = *string1 - *string2;
	DWORD isDebuggerPresent = 0;

	if (0x41 <= *string1 && *string1 < 0x5B)
		result += 0x20;
	if (0x41 <= *string2 && *string2 < 0x5B)
		result -= 0x20;

	string1++;
	string2++;

	if (!isDebuggerPresent)
	{
		__asm
		{
			push ebx;
			mov ebx, pPeb;
			mov ebx, [ebx];
			mov isDebuggerPresent, ebx;
			pop ebx;
		}
	}

	while (!result && *string1)
	{
		result = *string1 - *string2;

		if ((0x41 <= *string1 && *string1 < 0x5B) ^ ((isDebuggerPresent >> 16) & 0x01))
			result += 0x20;
		if (0x41 <= *string2 && *string2 < 0x5B)
			result -= 0x20;

		string1++;
		string2++;
	}

	if (result < 0)
		return -1;
	if (result > 0)
		return 1;

	return 0;
}
