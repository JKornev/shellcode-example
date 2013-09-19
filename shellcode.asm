
BITS 32 ;using x86 architecture

;---------------------------
;code block
entry_point:
pushad

call get_eip			
get_eip:
pop ebx 						;pop up virtual address to eax
sub ebx, get_eip - entry_point	;offset normalize

;arg4
push 0
;arg3
mov eax, msg_title
add eax, ebx
push eax
;arg2
mov eax, msg_string
add eax, ebx
push eax
;arg1
push 0
;call messagebox
mov eax, msgbox_addr
add eax, ebx
call [eax]

popad
retn

;---------------------------
;internal data block
msg_title: 		db 'Message', 0
msg_string:		db 'Hello Habra!', 0

;---------------------------
;input data block
msgbox_addr:	resd 1

