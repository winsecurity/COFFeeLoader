#pragma once

#include <Windows.h>

__forceinline ULONGLONG resolveexportforwarder(const char* forwardername);
__forceinline ULONGLONG getdllexportfunctionaddress(ULONGLONG dllbase, const char* functionnametofind);

__forceinline ULONGLONG getpebaddress() {
	// 0x60 offset of gs register contains peb address
	return __readgsqword(0x60);
}



void patchnormaladdress(char* patchaddress,ULONGLONG symboladdress ,WORD reloctype, LPVOID sectionbase) {
	
	if (reloctype == IMAGE_REL_AMD64_REL32) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4;
	}
	else if (reloctype == IMAGE_REL_AMD64_REL32_1) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4 - 1;
	}
	else if (reloctype == IMAGE_REL_AMD64_REL32_2) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4 - 2;
	}
	else if (reloctype == IMAGE_REL_AMD64_REL32_3) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4 - 3;
	}
	else if (reloctype == IMAGE_REL_AMD64_REL32_4) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4 - 4;
	}
	else if (reloctype == IMAGE_REL_AMD64_REL32_5) {
		*(DWORD*)patchaddress = symboladdress - (ULONGLONG)patchaddress - 4 - 5;
	}
	else if (reloctype == IMAGE_REL_AMD64_ADDR64) {
		*(ULONGLONG*)patchaddress = symboladdress;
	}

	else if (reloctype == IMAGE_REL_AMD64_ADDR32NB) {
		auto symbolrva = symboladdress - (ULONGLONG)sectionbase;
		*(DWORD*)patchaddress = symbolrva;

	}


}



__forceinline ULONGLONG getprocessbaseaddress() {

	ULONGLONG peb = __readgsqword(0x60);

	ULONGLONG processbaseaddress = *(ULONGLONG*)((char*)peb + 0x10);

	return processbaseaddress;
}



template <typename T, typename U>
__forceinline bool mystrcmp(const T* char1ptr, const U* char2ptr) {

	while (*char1ptr && *char2ptr) {

		char char1 = *char1ptr;
		char char2 = *char2ptr;


		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}


		if (char1 != char2) {
			return false;
		}

		char1ptr++;
		char2ptr++;

	}


	if (*char1ptr == 0 && *char2ptr == 0) {
		return true;
	}

	return false;

}



__forceinline ULONGLONG getdllbaseaddress(const char* dllnametofind) {

	ULONGLONG ppeb = __readgsqword(0x60);

	ULONGLONG ldr = *(ULONGLONG*)((char*)ppeb + 0x18);


	ULONGLONG firsttableentry = *(ULONGLONG*)((char*)ldr + 0x10);


	while (firsttableentry != ldr + 0x10) {

		ULONGLONG basedllname = *(ULONGLONG*)((char*)firsttableentry + 0x58 + 8);
		ULONGLONG dllbase = *(ULONGLONG*)((char*)firsttableentry + 0x30);

		if (mystrcmp<char, wchar_t>(dllnametofind, (const wchar_t*)basedllname)) {
			return  dllbase;
		}



		firsttableentry = *(ULONGLONG*)((char*)firsttableentry);

	}



	return 0;

}



__forceinline ULONGLONG getdllexportfunctionaddress(ULONGLONG dllbase, const char* functionnametofind) {


	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)dllbase;


	DWORD* signature = (DWORD*)((char*)dosheader + dosheader->e_lfanew);

	IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)((char*)dosheader + dosheader->e_lfanew + 4);


	IMAGE_OPTIONAL_HEADER64* optionalheader = (IMAGE_OPTIONAL_HEADER64*)((char*)dosheader +
		dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));


	if (optionalheader->DataDirectory[0].Size) {

		IMAGE_EXPORT_DIRECTORY* exportdirectory = (IMAGE_EXPORT_DIRECTORY*)((char*)dllbase + optionalheader->DataDirectory[0].VirtualAddress);


		char* dllname = (char*)dllbase + exportdirectory->Name;



		ULONGLONG eatptr = dllbase + exportdirectory->AddressOfFunctions;
		ULONGLONG entptr = dllbase + exportdirectory->AddressOfNames;
		ULONGLONG eotptr = dllbase + exportdirectory->AddressOfNameOrdinals;


		for (int i = 0;i < exportdirectory->NumberOfNames;i++) {

			DWORD namerva = *(DWORD*)((char*)entptr + i * 4);
			char* functionname = (char*)dllbase + namerva;

			WORD ordinal = *(WORD*)((char*)eotptr + i * 2);
			DWORD funcrva = *(DWORD*)((char*)eatptr + ordinal * 4);

			ULONGLONG functionaddress = dllbase + funcrva;

			if (mystrcmp<char, char>(functionname, functionnametofind)) {

				if (funcrva >= optionalheader->DataDirectory[0].VirtualAddress && (funcrva < (
					optionalheader->DataDirectory[0].VirtualAddress + optionalheader->DataDirectory[0].Size
					))) {
					// our function is export forwarder
					// NTDLL.RtlAcquireSRWLockExclusive
					return resolveexportforwarder((const char*)functionaddress);


				}

				return functionaddress;
			}


		}


	}

	return 0;
}


__forceinline ULONGLONG resolveexportforwarder(const char* forwardername) {

	// NTDLL.RtlAcquireSRWLockExclusive
	char dllnametofind[128]{ 0 }, functionnametofind[128]{ 0 };
	char* dllnametofindptr = dllnametofind, * functionnametofindptr = functionnametofind;

	const char* forwardernameptr = forwardername;

	while (*forwardernameptr != '.') {

		*dllnametofindptr = *forwardernameptr;

		dllnametofindptr++;
		forwardernameptr++;

	}
	forwardernameptr++;
	*dllnametofindptr = '.'; dllnametofindptr++;
	*dllnametofindptr = 'd'; dllnametofindptr++;
	*dllnametofindptr = 'l'; dllnametofindptr++;
	*dllnametofindptr = 'l'; dllnametofindptr++;

	while (*forwardernameptr != 0) {

		*functionnametofindptr = *forwardernameptr;

		functionnametofindptr++;
		forwardernameptr++;

	}

	auto forwarderdllbase = getdllbaseaddress(dllnametofind);
	if (forwarderdllbase) {
		return getdllexportfunctionaddress(forwarderdllbase, functionnametofind);
	}


	return 0;
}


__forceinline ULONGLONG getimportfirstthunk(ULONGLONG dllbase, const char* functionnametofind) {

	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)dllbase;


	DWORD* signature = (DWORD*)((char*)dosheader + dosheader->e_lfanew);

	IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)((char*)dosheader + dosheader->e_lfanew + 4);


	IMAGE_OPTIONAL_HEADER64* optionalheader = (IMAGE_OPTIONAL_HEADER64*)((char*)dosheader +
		dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));


	if (optionalheader->DataDirectory[1].Size) {

		IMAGE_IMPORT_DESCRIPTOR* importdescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)dllbase + optionalheader->DataDirectory[1].VirtualAddress);

		while (importdescriptor->Name) {

			char* dllname = (char*)dllbase + importdescriptor->Name;
			//std::cout << "Import dllname: " << dllname << std::endl;


			ULONGLONG* ogfirstthunkptr = (ULONGLONG*)((char*)dllbase + importdescriptor->OriginalFirstThunk);
			ULONGLONG* firstthunkptr = (ULONGLONG*)((char*)dllbase + importdescriptor->FirstThunk);

			while (*ogfirstthunkptr) {

				ULONGLONG funcnamerva = *ogfirstthunkptr + 2;
				char* functionname = (char*)dllbase + funcnamerva;

				if (mystrcmp<char, char>(functionname, functionnametofind)) {
					return (ULONGLONG)firstthunkptr;
				}

				//std::cout << "Function name: " << functionname << std::endl;

				//std::cout << "firstthunk: " << firstthunkptr << std::endl;


				ogfirstthunkptr++;
				firstthunkptr++;

			}


			importdescriptor++;

		}


	}

	return 0;

}

