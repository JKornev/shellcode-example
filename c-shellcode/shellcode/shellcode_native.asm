;IA86 and AMD64
IFDEF _M_IA86
.386
.model flat, stdcall
ENDIF

;set code section .shell
.CODE shell

;data struct
Shell_Static_Data STRUCT 
	phrase_ldrloaddll db 16 dup(0)
	phrase_msgbox db 16 dup(0)
	phrase_hello db 16 dup(0)
	phrase_hello_title db 16 dup(0)
	phrase_user32 dw 16 dup(0)
	phrase_ntdll dw 16 dup(0)
Shell_Static_Data ENDS

shelldata Shell_Static_Data <"LdrLoadDll", "MessageBoxA", "Hello hacker", "Shellcode", \
	 {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l'}, {'N', 't', 'd', 'l','l', '.', 'd', 'l', 'l'}>


;getting ptr to shelldata struct

IFDEF _M_IA86

get_data_struct_ptr PROC
;delta
	call get_delta
get_delta:
	pop eax
;calc var
	sub eax, 5
	sub eax, sizeof shelldata
	ret
get_data_struct_ptr ENDP

ELSEIFDEF _M_AMD64

get_data_struct_ptr PROC
;delta
	call get_delta
get_delta:
	pop rax
;calc var
	sub rax, 5
	sub rax, sizeof shelldata
	ret
get_data_struct_ptr ENDP

ENDIF

END