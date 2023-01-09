.code

extern vmx_exit_handler:proc

asm_get_gdt_table proc

sgdt [rcx]
ret

asm_get_gdt_table endp


asm_get_es proc

xor eax,eax
mov ax,es
ret

asm_get_es endp

asm_get_cs proc

xor eax,eax
mov ax,cs
ret


asm_get_cs endp


asm_get_ss proc
xor eax,eax
mov ax,ss
ret
asm_get_ss endp

asm_get_ds proc

xor eax,eax
mov ax,ds
ret

asm_get_ds endp

asm_get_fs proc

xor eax,eax
mov ax,fs
ret

asm_get_fs endp

asm_get_gs proc

xor eax,eax
mov ax,gs
ret


asm_get_gs endp

asm_get_tr proc

xor eax,eax
str ax
ret

asm_get_tr endp

asm_get_ldtr proc

xor eax,eax
sldt ax
ret

asm_get_ldtr endp

asm_vmx_exit_handler proc
	push r15;
	push r14;
	push r13;
	push r12;
	push r11;
	push r10;
	push r9;
	push r8;
	push rdi;
	push rsi;
	push rbp;
	push rsp;
	push rbx;
	push rdx;
	push rcx;
	push rax;
	
	mov rcx,rsp;
	sub rsp,0100h
	call vmx_exit_handler
	add rsp,0100h;

	pop rax;
	pop rcx;
	pop rdx;
	pop rbx;
	pop rsp;
	pop rbp;
	pop rsi;
	pop rdi;
	pop r8;
	pop r9;
	pop r10;
	pop r11;
	pop r12;
	pop r13;
	pop r14;
	pop r15;
	vmresume
	ret
asm_vmx_exit_handler endp

asm_invd proc

invd
ret

asm_invd endp

asm_vm_call proc
	mov rax,rcx ;flags
	vmcall
	ret
asm_vm_call endp

asm_jmup_target proc

	mov rsp,rdx

	jmp rcx

asm_jmup_target endp

end

