#include <stdio.h>
#include <Windows.h>

#include "shellcode.h"


uintptr_t unpack_shellcode(char *exe_path, char *save_path)
{
	HANDLE hfile = INVALID_HANDLE_VALUE, hmap = NULL;
	uintptr_t size, offset = 0, i;
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPTIONAL_HEADER32 popt32;
	PIMAGE_OPTIONAL_HEADER64 popt64;
	PIMAGE_SECTION_HEADER psects, psect = NULL;
	char sect_name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
	char *pshell_buf;
	DWORD written;
	LPVOID pview = NULL;

	__try {
		hfile = CreateFileA(exe_path, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			printf("Error, can't open file!\n");
			return 0;
		}

		hmap = CreateFileMapping(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (!hmap) {
			printf("Error, can't mapped file!\n");
			return 0;
		}
		CloseHandle(hfile);
		hfile = INVALID_HANDLE_VALUE;

		pview = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
		if (!pview) {
			printf("Error, can't mapped file!\n");
			return 0;
		}

		//parse DOS and PE header
		pdos = (PIMAGE_DOS_HEADER)pview;
		if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("Error, incorrect DOS header!\n");
			return 0;
		}
		offset += pdos->e_lfanew;

		if (*(DWORD *)((uintptr_t)pdos + offset) != (DWORD)IMAGE_NT_SIGNATURE) {
			printf("Error, incorrect PE header!\n");
			return 0;
		}
		offset += 4;

		pimg = (PIMAGE_FILE_HEADER)((uintptr_t)pdos + offset);
		offset += sizeof(IMAGE_FILE_HEADER);

		if (pimg->Machine != IMAGE_FILE_MACHINE_I386 && pimg->Machine != IMAGE_FILE_MACHINE_AMD64) {
			printf("Error, incorrect architecture!\n");
			return 0;
		}

		if (pimg->Machine == IMAGE_FILE_MACHINE_I386) {
			popt32 = (PIMAGE_OPTIONAL_HEADER32)((uintptr_t)pdos + offset);
			offset += sizeof(IMAGE_OPTIONAL_HEADER32);
		} else {
			popt64 = (PIMAGE_OPTIONAL_HEADER64)((uintptr_t)pdos + offset);
			offset += sizeof(IMAGE_OPTIONAL_HEADER64);
		}

		psects = (PIMAGE_SECTION_HEADER)((uintptr_t)pdos + offset);

		//search shell section
		for (i = 0; i < pimg->NumberOfSections; i++) {
			memcpy(sect_name, psects[i].Name, IMAGE_SIZEOF_SHORT_NAME);
			if (!strcmp(sect_name, SHELLCODE_SECTION)) {
				psect = &psects[i];
				break;
			}
		}
		if (!psect) {
			printf("Error, shellcode section not found!\n");
			return 0;
		}

		//shink shellcode size
		size = 0;
		pshell_buf = (char *)((uintptr_t)pdos + psect->PointerToRawData);
		for (i = psect->SizeOfRawData - 1; i >= 0; i--) {
			if (pshell_buf[i] != 0 && pshell_buf[i] != 0xCC) {
				size = i + 1;
				break;
			}
		}

		//save shellcode
		hfile = CreateFileA(save_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NULL, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			printf("Error, can't open output file!\n");
			return 0;
		}

		if (!WriteFile(hfile, pshell_buf, size, &written, NULL)) {
			printf("Error, can't write to output file!\n");
			return 0;
		}

	} __finally {
		if (hfile != INVALID_HANDLE_VALUE) {
			CloseHandle(hfile);
		}
		if (hmap) {
			CloseHandle(hmap);
		}
		if (pview) {
			UnmapViewOfFile(pview);
		}
	}
	
	return 1;
}

uintptr_t load_shellcode(char *path)
{
	HANDLE hfile;
	unsigned int size, readed;
	char *pbuf;
	void *pspace;

	hfile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't open shellcode!\n");
		return 0;
	}

	size = GetFileSize(hfile, NULL);
	if (!size) {
		printf("Error, file is empty\n");
		return 0;
	}

	pbuf = (char *)malloc(size);

	if (!ReadFile(hfile, pbuf, size, (LPDWORD)&readed, NULL)) {
		printf("Error, can't read shellcode data\n");
		free(pbuf); return 0;
	}

	pspace = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pspace) {
		printf("Error, can't allocate virtual page\n");
		free(pbuf); return 0;
	}

	memcpy(pspace, pbuf, size);

	((void (*)())pspace)();//call shellcode

	VirtualFree(pspace, size, MEM_DECOMMIT);

	return 1;
}

int main(int argc, char *argv[])
{
	//unpack shellcode to file
	if (!unpack_shellcode(argv[0], SHELLCODE_FILE)) {
		return 1;
	}
	printf("Unpacking successful!\n");

	//for compile and debug
	printf("Calling shellcode from module!\n");
	entry();

	//for test
	printf("Calling shellcode from random base!\n");
	if (!load_shellcode(SHELLCODE_FILE)) {
		return 1;
	}

	return 0;
}