extern g_orig_system_call:dq
extern g_hook_enable:DB
extern g_arg_tble:DB
extern g_hook_table:DQ
extern g_KiServiceCopyEndPtr:DQ
extern g_CountNumCheckPtr:DQ
extern g_KeServiceDescriptorTable:DQ
extern g_KiSystemServiceRepeatPtr:DQ
extern g_KiSaveDebugRegisterState:DQ
extern g_KiUmsCallEntry:DQ
extern g_is_win7:DQ
MAX_SYSCALL_INDEX = 1000h
USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h
.code

asm_stac proc

stac

ret

asm_stac endp
fake_kisystemcall64 proc
swapgs
;int 3
mov gs:[USERMD_STACK_GS], rsp
cmp rax, MAX_SYSCALL_INDEX
jge KiSystemCall64
lea rsp, offset g_hook_enable
cmp byte ptr [rsp + rax], 0
jne KiSystemCall64_Emulate
fake_kisystemcall64 endp
KiSystemCall64 PROC
mov rsp, gs:[USERMD_STACK_GS]
swapgs
jmp [g_orig_system_call]
KiSystemCall64 ENDP
KiSystemCall64_Emulate PROC
mov rsp, gs:[KERNEL_STACK_GS] ; set kernel stack pointer
push 2Bh ; push dummy SS selector
push qword ptr gs:[10h] ; push user stack pointer
push r11 ; push previous EFLAGS
push 33h ; push dummy 64-bit CS selector
push rcx ; push return address
mov rcx, r10 ; set first argument value
sub rsp, 8h ; allocate dummy error code
push rbp ; save standard register
sub rsp, 158h ; allocate fixed frame
lea rbp, [rsp+80h] ; set frame pointer
mov [rbp+0C0h], rbx ; save nonvolatile registers
mov [rbp+0C8h], rdi ;
mov [rbp+0D0h], rsi ;
mov byte ptr [rbp-55h], 2h ; set service active
mov rbx, gs:[188h] ; get current thread address
prefetchw byte ptr [rbx+90h] ; prefetch with write intent
stmxcsr dword ptr [rbp-54h] ; save current MXCSR
ldmxcsr dword ptr gs:[180h] ; set default MXCSR
cmp byte ptr [rbx+3], 0 ; test if debug enabled
mov word ptr [rbp+80h], 0 ; assume debug not enabled
jz KiSS05 ; if z, debug not enabled
mov [rbp-50h], rax ; save service argument registers
mov [rbp-48h], rcx ;
mov [rbp-40h], rdx ;
mov [rbp-38h], r8 ;
mov [rbp-30h], r9 ;
je a2
call [g_KiSaveDebugRegisterState]
align 10h
a2:
test byte ptr [rbx+3],80h
je a3
mov ecx,0C0000102h
rdmsr
shl rdx,20h
or rax,rdx
a3:
cmp qword ptr [rbx+0B8h],rax
je B0
cmp qword ptr [rbx+1B0h],rax
je B0
mov rdx,qword ptr [rbx+1B8h]
bts dword ptr [rbx+4Ch],0Bh
dec word ptr [rbx+1C4h]
mov qword ptr [rdx+80h],rax
sti
call [g_KiUmsCallEntry]
jmp FA0
B0:
test byte ptr [rbx+3],40h
je FA0
lock bts dword ptr [rbx+100h],8
FA0:
mov rax,qword ptr [rbp-50h]
mov rcx,qword ptr [rbp-48h]
mov rdx,qword ptr [rbp-40h]
mov r8,qword ptr [rbp-38h]
mov r9,qword ptr [rbp-30h]
xchg ax,ax
KiSS05:
sti
cmp byte ptr [g_is_win7], 0
jne WIN7;
mov [rbx+88h], rcx
mov [rbx+80h], eax
jmp KiSystemServiceStart_Emulate
WIN7:
mov qword ptr [rbx+1E0h],rcx
mov dword ptr [rbx+1F8h],eax
KiSystemCall64_Emulate ENDP
KiSystemServiceStart_Emulate PROC
mov [rbx+90h], rsp ;save to thread
mov edi, eax
shr edi, 7
and edi, 20h
and eax, 0FFFh
KiSystemServiceStart_Emulate ENDP
KiSystemServiceRepeat_Emulate PROC
; RAX = [IN ] syscall index
; RAX = [OUT] number of parameters
; R10 = [OUT] function address
; R11 = [I/O] trashed
lea r11, offset g_hook_table
mov r10, qword ptr [r11 + rax * 8h]
lea r11, offset g_arg_tble
movzx rax, byte ptr [r11 + rax] ; RAX = paramter count
jmp [g_KiServiceCopyEndPtr] ;bug not check paramter count and jmp 这里有个BUG Hook超过4个syscall会寄
KiSystemServiceRepeat_Emulate ENDP
end


