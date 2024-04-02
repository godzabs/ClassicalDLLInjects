#include "header.h"


HMODULE returnModuleHandle(PWSTR libName) {
	HMODULE addrToLibrary = NULL;
	//printf("[+] size of LDR_DATA_TABLE_ENTRY struct = %d\n",sizeof(LIST_ENTRY));
#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#elif __WIN32
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
	PPEB_LDR_DATA pldrData = pPEB->Ldr;
	PLIST_ENTRY lHead = &(pldrData->InMemoryOrderModuleList);
	PLIST_ENTRY lStop = &(pldrData->InMemoryOrderModuleList);
	while (lHead->Flink != lStop) {
		PMY_LDR_DATA_TABLE_ENTRY data = (PMY_LDR_DATA_TABLE_ENTRY)((LPBYTE)lHead - sizeof(LIST_ENTRY));
		//wprintf(L"%s\n",(PWSTR)data->BaseDllName.Buffer);
		if ((PWSTR)data->BaseDllName.Buffer == NULL) {
			lHead = lHead->Flink;
			continue;
		}
		else if (0 == _wcsicmp((PWSTR)data->BaseDllName.Buffer, libName)) {
		//wprintf(L"[+] Found %s !, addr = 0x%p", libName, (PBYTE)data->DllBase);
			addrToLibrary = (HMODULE)data->DllBase;
			break;
		}
		lHead = lHead->Flink;

	}
	return addrToLibrary;
}


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

