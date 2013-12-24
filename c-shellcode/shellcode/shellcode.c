#include "shellcode.h"
#include <stdio.h>

#pragma code_seg("shell")

uintptr_t str_cmpw(wchar_t *str1, wchar_t *str2);
uintptr_t str_cmp(char *str1, char *str2);
uintptr_t str_len(char *str);
uintptr_t str_lenw(wchar_t *str);

// Shellcode entry point
__declspec(noinline) void entry()
{
	PShell_Static_Data shelldata = (PShell_Static_Data)get_data_struct_ptr();
	void *ntdll = get_module_base_addr(shelldata->phrase_ntdll);
	void *kernel32;
	LdrLoadDllProc LdrLoadDll = (LdrLoadDllProc)get_proc_addr(ntdll, shelldata->phrase_ldrloaddll);
	MessageBoxProc MsgBox;
	UNICODE_STRING uni;

	uni.Buffer = shelldata->phrase_user32;
	uni.Length = str_lenw(uni.Buffer) * 2;
	uni.MaximumLength = uni.Length + 2;
	if (LdrLoadDll(NULL, 0, &uni, &kernel32)) {
		return;
	}

	MsgBox = (MessageBoxProc)get_proc_addr(kernel32, shelldata->phrase_msgbox);

	MsgBox(NULL, shelldata->phrase_hello, shelldata->phrase_hello_title, MB_OK);
}

// Get module base address
void *get_module_base_addr(wchar_t *mod_name)
{
	PPEB peb = (PPEB)GET_PEB;
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY ldr_entry = (PLDR_DATA_TABLE_ENTRY)((uintptr_t)ldr->InMemoryOrderModuleList.Blink - (sizeof(uintptr_t) * 2));
	PLDR_DATA_TABLE_ENTRY ldr_first;

	ldr_first = ldr_entry;
	do {
		if (ldr_entry->DllBase && str_cmpw(ldr_entry->BaseDllName.Buffer, mod_name)) {
			return (HMODULE)ldr_entry->DllBase;
		}
		ldr_entry = (PLDR_DATA_TABLE_ENTRY)((uintptr_t)ldr_entry->InMemoryOrderLinks.Blink - (sizeof(uintptr_t) * 2));
	} while (ldr_first != ldr_entry);

	return NULL;
}

// Get export procedure address
void *get_proc_addr(void *mod_addr, char *proc_name)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPT_HEADER popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	PDWORD pnames, pfuncs;
	PWORD pords;
	uintptr_t i;
	char *proc;

	//getting export directory
	pdos = (PIMAGE_DOS_HEADER)mod_addr;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	popt = (PIMAGE_OPTIONAL_HEADER)((uintptr_t)mod_addr + pdos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (uintptr_t)mod_addr);
	if (!pexp) {//export not found
		return NULL;
	}

	//searching function name
	pnames = (PDWORD)(pexp->AddressOfNames + (uintptr_t)mod_addr);
	pords = (PWORD)(pexp->AddressOfNameOrdinals + (uintptr_t)mod_addr);
	pfuncs = (PDWORD)(pexp->AddressOfFunctions + (uintptr_t)mod_addr);

	for (i = 0; i < pexp->NumberOfNames; i++) {
		proc = (char *)(pnames[i] + (uintptr_t)mod_addr);
		if (str_cmp(proc, proc_name)) {
			break;
		}
	}
	if (i == pexp->NumberOfNames) {//not found
		return NULL;
	}

	return (void *)(pfuncs[pords[i]] + (uintptr_t)mod_addr);
}


// String compare (non case-sensitive)
uintptr_t str_cmp(char *str1, char *str2)
{
	int i = 0;
	char char1, char2;
	for (i = 0; ; i++) {
		char1 = str1[i];
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		char2 = str2[i];
		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}

		if (char1 != char2) {
			break;
		}
		if (!char1) {
			return 1;
		}
	}
	return 0;
}

// Unicode string compare (non case-sensitive)
uintptr_t str_cmpw(wchar_t *str1, wchar_t *str2)
{
	int i = 0;
	wchar_t char1, char2;
	for (i = 0; ; i++) {
		char1 = str1[i];
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		char2 = str2[i];
		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}

		if (char1 != char2) {
			break;
		}
		if (!char1) {
			return 1;
		}
	}
	return 0;
}

// String length
uintptr_t str_len(char *str)
{
	uintptr_t i = 0;
	for (i = 0; ; i++) {
		if (!str[i]) {
			return i;
		}
	}
	return 0;
}

// Unicode string length
uintptr_t str_lenw(wchar_t *str)
{
	uintptr_t i = 0;
	for (i = 0; ; i++) {
		if (!str[i]) {
			return i;
		}
	}
	return 0;
}