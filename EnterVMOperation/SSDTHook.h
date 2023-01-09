#pragma once
#define MAX_SYSCALL_INDEX 0x1000
#define SYSHOOK_TAG 'Hook'

EXTERN_C void asm_stac();
//extern "C" {
//
//	UINT64 g_orig_system_call = 0;
//	CHAR g_hook_enable[MAX_SYSCALL_INDEX] = { 0 };
//	CHAR g_arg_tble[MAX_SYSCALL_INDEX] = { 0 };
//	PULONG g_hook_table[MAX_SYSCALL_INDEX] = { 0 };
//	UINT64 g_KiServiceCopyEndPtr = 0;
//	UINT64 g_CountNumCheckPtr = 0;
//	UINT64 g_KeServiceDescriptorTable = 0;
//	UINT64 g_KiSystemServiceRepeatPtr = 0;
//	UINT64 g_KiSaveDebugRegisterState = 0;
//	UINT64 g_KiUmsCallEntry = 0;
//	UINT64 g_is_win7 = 0;
//
//}

typedef struct _SYSTEM_SERVICE_TABLE {
	PLONG  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

class SyscallHook {
public:
	SyscallHook();
	~SyscallHook();
	bool fn_add_hook_by_index(ULONG syscall_index,UINT64 new_func);
	bool fn_remove_hook_by_index(ULONG syscall_index);
	static SyscallHook* GetInsctance();
	bool fn_syshook_init(UINT64 old_ssdt, UINT64 g_KiServiceCopyEndPtr, UINT64 g_KiSaveDebugRegisterState, UINT64 g_KiUmsCallEntry, UINT64 is_win7);
	bool fn_remove_all_hooks();
private:
	static SyscallHook* Instance;
};

