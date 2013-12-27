//Loader.c
#include <Windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	HANDLE hfile;
	unsigned int size, readed;
	char *pbuf;
	void *pspace;

	if (argc < 2) {
		printf("Error, arguments missmatch\n");
		return 1;
	}

	hfile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't open shellcode '%s' (code %d)\n", argv[1], GetLastError());
		return 2;
	}

	size = GetFileSize(hfile, NULL);
	if (!size) {
		printf("Error, file is empty\n");
		return 3;
	}

	pbuf = (char *)malloc(size);

	if (!ReadFile(hfile, pbuf, size, (LPDWORD)&readed, NULL)) {
		printf("Error, can't read shellcode data\n");
		free(pbuf); return 4;
	}

	pspace = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pspace) {
		printf("Error, can't allocate virtual page\n");
		free(pbuf); return 5;
	}

	memcpy(pspace, pbuf, size);

	((void (*)())pspace)();//call shellcode

	VirtualFree(pspace, 0, MEM_RELEASE);
	free(pbuf);
	return 0;
}