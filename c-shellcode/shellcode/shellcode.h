#pragma once

#include <Windows.h>
#include <intrin.h>


#define SHELLCODE_FILE "shellcode.bin"
#define SHELLCODE_SECTION "shell"


#if defined(_M_IA86)
#define GET_PEB __readfsdword(0x30)
#define PIMAGE_OPT_HEADER PIMAGE_OPTIONAL_HEADER32
#elif defined(_M_AMD64)
#define GET_PEB __readgsqword(0x60)
#define PIMAGE_OPT_HEADER PIMAGE_OPTIONAL_HEADER64
#else
#error Architechure not supported!
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


#pragma pack(push, 1)
typedef struct _Shell_Static_Data {
	char phrase_ldrloaddll[16];
	char phrase_msgbox[16];
	char phrase_hello[16];
	char phrase_hello_title[16];
	wchar_t phrase_user32[16];
	wchar_t phrase_ntdll[16];
} Shell_Static_Data, *PShell_Static_Data;
#pragma pack(pop)

extern PShell_Static_Data __stdcall get_data_struct_ptr();

__declspec(noinline) void entry();

void *get_module_base_addr(wchar_t *mod_name);
void *get_proc_addr(void *mod_addr, char *proc_name);

typedef NTSTATUS (NTAPI *LdrLoadDllProc)(PWCHAR PathToFile, ULONG Flags, UNICODE_STRING *ModuleFileName, void **ModuleHandle);
typedef int (WINAPI *MessageBoxProc)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
