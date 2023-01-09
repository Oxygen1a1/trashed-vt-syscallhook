#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "SSDTHook.h"
#include "msr.h"
#include "vmx.h"

EXTERN_C void fake_kisystemcall64();

extern "C" {

	UINT64 g_orig_system_call = 0;
	CHAR g_hook_enable[MAX_SYSCALL_INDEX] = { 0 };
	CHAR g_arg_tble[MAX_SYSCALL_INDEX] = { 0 };
	UINT64 g_hook_table[MAX_SYSCALL_INDEX] = { 0 };
	UINT64 g_KiServiceCopyEndPtr = 0;
	UINT64 g_CountNumCheckPtr = 0;
	UINT64 g_KeServiceDescriptorTable = 0;
	UINT64 g_KiSystemServiceRepeatPtr = 0;
	UINT64 g_KiSaveDebugRegisterState = 0;
	UINT64 g_KiUmsCallEntry = 0;
	UINT64 g_is_win7 = 0;

}

SyscallHook* SyscallHook::Instance;




SyscallHook* SyscallHook::GetInsctance() {

	if (!Instance) {

		Instance = (SyscallHook*)ExAllocatePoolWithTag(PagedPool, sizeof(SyscallHook), SYSHOOK_TAG);
	}

	return Instance;

}

SYSTEM_SERVICE_TABLE* g_uOldSsdt;

SyscallHook::SyscallHook() {



}

SyscallHook::~SyscallHook() {


}

bool SyscallHook::fn_add_hook_by_index(ULONG syscall_index, UINT64 new_func)
{
	SYSTEM_SERVICE_TABLE* Ssdt = (SYSTEM_SERVICE_TABLE*)g_KeServiceDescriptorTable;
	UINT64 oSysCallFunc = 0;
	ULONG uOffset = Ssdt->ServiceTableBase[syscall_index];

	//获取参数
	CHAR CountOfParam = uOffset & 0XF;

	uOffset = (uOffset & ~0xf) >> 4;

	oSysCallFunc = uOffset + (UINT64)Ssdt->ServiceTableBase;

	//填充hook表 和enable表以及arg表

	g_hook_enable[syscall_index] = true;
	g_arg_tble[syscall_index] = CountOfParam;

	//自己的KiSyscall是直接查表 不用指针
	g_hook_table[syscall_index] = new_func;

	return true;
}

bool SyscallHook::fn_remove_hook_by_index(ULONG syscall_index)
{
	::g_hook_enable[syscall_index] = false;

	return true;
}

#pragma warning(disable : 4459)
bool SyscallHook::fn_syshook_init(UINT64 old_ssdt, UINT64 g_KiServiceCopyEndPtr, UINT64 g_KiSaveDebugRegisterState, UINT64 g_KiUmsCallEntry, UINT64 is_win7)
{
	

	::g_KeServiceDescriptorTable = old_ssdt;
	::g_KiServiceCopyEndPtr = g_KiServiceCopyEndPtr;
	::g_KiSaveDebugRegisterState = g_KiSaveDebugRegisterState;
	::g_KiUmsCallEntry = g_KiUmsCallEntry;
	::g_is_win7 =is_win7;

	//保存原来的IA32_LSTAR
	g_orig_system_call = (UINT64)__readmsr(0xC0000082);

	__writemsr(0xC0000082, (UINT64)fake_kisystemcall64);
	//参数表和Hook表在syshook的时候单个填充

	return true;
}

bool SyscallHook::fn_remove_all_hooks()
{
	//必须在退出VT之后使用 否则会被拦截
	__writemsr(0xC0000082, g_orig_system_call);

	return true;
}
