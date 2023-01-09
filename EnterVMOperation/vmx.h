#pragma once
int vmm_init(unsigned long long vm_exit_handler);
void vmm_exit();
#pragma pack(push,1)
typedef struct _GdtTable
{
	UINT16 limit;
	ULONG64 Base;
}GdtTable, * PGdtTable;
#pragma pack(pop)
EXTERN_C void asm_get_gdt_table(PVOID);
EXTERN_C  unsigned short asm_get_es(VOID);
EXTERN_C  unsigned short asm_get_ds(VOID); 
EXTERN_C  unsigned short asm_get_ss(VOID); 
EXTERN_C  unsigned short asm_get_fs(VOID);
EXTERN_C  unsigned short asm_get_gs(VOID);
EXTERN_C  unsigned short asm_get_cs(VOID);
EXTERN_C unsigned short asm_get_tr(VOID);
EXTERN_C unsigned short asm_get_ldtr(VOID);
EXTERN_C void asm_vmx_exit_handler();
EXTERN_C void asm_invd();
EXTERN_C void asm_vm_call(UINT64 exit_code);
EXTERN_C void asm_jmup_target(UINT64 rip, UINT64 rsp);
