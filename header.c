#include "header.h"

VOID* returnGetProcAddress(HMODULE lpBaseofDLL, char* functionName) {
	PVOID addrOfGetProc = NULL;
	PIMAGE_DOS_HEADER pAddr = (PIMAGE_DOS_HEADER)lpBaseofDLL;
	//There is one for 32/64 bit, but in the header file there is a #ifdef for each
	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((LPBYTE)pAddr + pAddr->e_lfanew); //Offset to extended header, PE signature 
	PIMAGE_DATA_DIRECTORY pOpt = (PIMAGE_DATA_DIRECTORY)&pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pAddr + pOpt->VirtualAddress);

	PDWORD pAddrOfNames = (PDWORD)((LPBYTE)pAddr + pExport->AddressOfNames);
	PDWORD pAddrOfFunc = (PDWORD)((LPBYTE)pAddr + pExport->AddressOfFunctions);
	PWORD pAddrOfNameOrd = (PWORD)((LPBYTE)pAddr + pExport->AddressOfNameOrdinals); //This needs to be a Pointer to WORD(unsigned short short)
	for (int i = 0; i < pExport->NumberOfNames; i++) {
		char* funcName = (char*)((LPBYTE)pAddr + pAddrOfNames[i]);
		if (0 == _stricmp(functionName, funcName)) {
			printf("[!] Found GetProcAddress!\n");
			addrOfGetProc = (FARPROC)((LPBYTE)pAddr + pAddrOfFunc[pAddrOfNameOrd[i]]); // I spent 2 hours trying to figure out why this was not working
																			 // Turns out the Ordinal number is in 2 byte units, so you have to cast to USHORT(OR WORD)
																			// https://sachiel-archangel.medium.com/how-to-analyze-api-address-acquisition-process-696750f50039
			break;
		}
	}
	return addrOfGetProc;
}

