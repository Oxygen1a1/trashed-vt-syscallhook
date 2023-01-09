#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "Struct.h"
#include "vmcscode.h"
#include "msr.h"
#include "vmx.h"

__vmm_context_t* gVmmContext;


#pragma warning(disable : 4244)

//初始化vmcs的host字段
void init_vmcs_host(__vcpu_t* vcpu,unsigned long long host_rip);

//初始化vmcs的guest字段
void init_vmcs_guest(void* guest_rsp, void (*guest_rip)());

//初始化vm entry 控制
void init_vmcs_entry_controls();

//初始化vm exit控制
void init_vmcs_exit_controls();

//初始化vm executation control
//用于控制什么指令vm exit
void init_vmcs_vmexecute_controls(__vcpu_t* vcpu);

void full_vmcs_segemnt_atrributes(unsigned int index,short selector);



//调整值
unsigned long long vmx_adjust_entry_control(unsigned int vaule, unsigned int msr);

//初始化虚拟cpu上下文
struct __vcpu_t* init_vcpu(void)
{
	PHYSICAL_ADDRESS lowphys, heiPhy;
	lowphys.QuadPart = 0;
	heiPhy.QuadPart = -1;
	__vcpu_t* vcpu = nullptr;

	vcpu = (__vcpu_t*)ExAllocatePoolWithTag(NonPagedPool, sizeof(__vcpu_t), VMM_TAG);

	if (!vcpu) {

		DbgPrintEx(77, 0, "[+]failed to alloc memory  Line==%d\r\n", __LINE__);

		return nullptr;
	}

	//分配MSR位图
	vcpu->msr_bitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMM_TAG);


	//RtlSecureZeroMemory(vcpu, sizeof(struct __vcpu_t));

	RtlSecureZeroMemory(vcpu->msr_bitmap, PAGE_SIZE);

	vcpu->msr_bitmap_physical = MmGetPhysicalAddress(vcpu->msr_bitmap).QuadPart;


	//分配vCpu的堆栈
	vcpu->stack_top= MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 6, lowphys, heiPhy, lowphys, MmCached);

	if (!vcpu->stack_top) {

		DbgPrintEx(77, 0, "[+]failed to alloc memory  Line==%d\r\n", __LINE__);
		return 0;
	}

	memset(vcpu->stack_top, 0xcc, PAGE_SIZE * 6);

	vcpu->stack_base = (void*)((UINT64)vcpu->stack_top + PAGE_SIZE * 6 - 0x200);

	DbgPrintEx(77, 0, "[+]vcpu alloc at %llx\r\n",vcpu);

	return vcpu;
};

void exit_logical_processor(__vcpu_t* vcpu) {

	if (vcpu->msr_bitmap && MmIsAddressValid(vcpu->msr_bitmap)) {

		ExFreePool(vcpu->msr_bitmap);

	}
	if (vcpu->stack_top && MmIsAddressValid(vcpu->stack_top)) {

		MmFreeContiguousMemorySpecifyCache(vcpu->stack_top, PAGE_SIZE * 6, MmCached);

	}

	if (vcpu->vmcs && MmIsAddressValid(vcpu->vmcs)) {

		MmFreeContiguousMemory(vcpu->vmcs);

	}

	if (vcpu->vmxon && MmIsAddressValid(vcpu->vmxon)) {

		MmFreeContiguousMemory(vcpu->vmxon);
	}

	//关闭VMX位
	__cr4_t cr4;
	cr4.control = __readcr4();
	
	cr4.bits.vmx_enable = false;

	__writecr4(cr4.control);
}


void vmm_exit() {

	GROUP_AFFINITY Affinity, OldAffinity;
	PROCESSOR_NUMBER ProcessorNumber{0};
	__vmm_context_t* vmm_context = gVmmContext;

	for (int i = 0; i < vmm_context->processor_count; i++) {

		//遍历每个vCpuIndex

		KeGetProcessorNumberFromIndex(i, &ProcessorNumber);

		//切换线程执行销毁处理

		Affinity.Mask = (KAFFINITY)1 << ProcessorNumber.Number;
		Affinity.Group = ProcessorNumber.Group;
		KeSetSystemGroupAffinityThread(&Affinity, &OldAffinity);

		asm_vm_call('exit');

		exit_logical_processor(vmm_context->vcpu_table[i]);

		KeRevertToUserGroupAffinityThread(&OldAffinity);


	}




}
//初始化vmm上下文
struct __vmm_context_t* allocate_vmm_context(void) {

	struct __vmm_context_t* vmm_context = nullptr;

	vmm_context = (struct __vmm_context_t*)(ExAllocatePoolWithTag(NonPagedPool, sizeof(__vmm_context_t), VMM_TAG));

	if (!vmm_context) {

		DbgPrintEx(77, 0, "[+]failed to alloc memory  Line==%d\r\n",__LINE__);

		return nullptr;
	}

	//填充VMM上下文
	vmm_context->processor_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	vmm_context->stack = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, VMM_TAG);

	vmm_context->vcpu_table=(struct __vcpu_t**)ExAllocatePoolWithTag(NonPagedPool, sizeof(struct __vcpu_t*) * vmm_context->processor_count, VMM_TAG);

	//设置VMM堆栈为CC

	memset(vmm_context->stack, 0xCC, VMM_STACK_SIZE);

	DbgPrintEx(77,0,"[+]vmm_context allocated at %llX\n", vmm_context);
	DbgPrintEx(77,0,"[+]vcpu_table allocated at %llX\n", vmm_context->vcpu_table);
	DbgPrintEx(77,0,"[+]vmm stack allocated at %llX\n", vmm_context->stack);

	return vmm_context;
}

//初始化vmxon区域
int init_vmxon(__vcpu_t* vcpu) {
	__vmx_basic_msr_t vmx_basic = { 0 };
	__vmcs_t* vmxon;
	PHYSICAL_ADDRESS physical_max;

	physical_max.QuadPart = MAXULONG64;

	if (!vcpu) {

		DbgPrintEx(77, 0, "[+]vcpu was nullptr\r\n");

		return false;
	}

	vmx_basic.control = __readmsr(IA32_VMX_BASIC_MSR);

	//判断vmxon区域多大
	if (vmx_basic.bits.vmxon_region_size > PAGE_SIZE) {
		vcpu->vmxon = (__vmcs_t*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
	}
	else {

		vcpu->vmxon = (__vmcs_t*)MmAllocateContiguousMemory(vmx_basic.bits.vmxon_region_size, physical_max);
	}

	vcpu->vmxon_physical = MmGetPhysicalAddress(vcpu->vmxon).QuadPart;
	vmxon = vcpu->vmxon;

	RtlSecureZeroMemory(vmxon, sizeof(PAGE_SIZE));

	vmxon->header.all = vmx_basic.bits.vmcs_revision_identifier;

	DbgPrintEx(77,0,"[+]VMXON for vcpu %d initialized:\n\t-> VA: %llX\n\t-> PA: %llX\n\t-> REV: %X\n",
		KeGetCurrentProcessorNumber(),
		vcpu->vmxon,
		vcpu->vmxon_physical,
		vcpu->vmxon->header.all);
	return TRUE;
}



//初始化vmcs区域
int init_vmcs(struct __vcpu_t* vcpu, void* guest_rsp, void (*guest_rip)()) {


	//获取host_rip;
	unsigned long long vm_exit_handler = vcpu->vmm_context->vm_exit_handler;

	struct __vmcs_t* vmcs;
	union __vmx_basic_msr_t vmx_basic = { 0 };
	PHYSICAL_ADDRESS physical_max;


	//确定硬件VMCS的大小
	vmx_basic.control = __readmsr(IA32_VMX_BASIC_MSR);

	physical_max.QuadPart = ~0ULL;
	vcpu->vmcs = (__vmcs_t*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
	vcpu->vmcs_physical = MmGetPhysicalAddress(vcpu->vmcs).QuadPart;

	RtlSecureZeroMemory(vcpu->vmcs, PAGE_SIZE);

	//填充VMCS
	vmcs = vcpu->vmcs;
	vmcs->header.all = vmx_basic.bits.vmcs_revision_identifier;
	vmcs->header.bits.shadow_vmcs_indicator = 0;
	
	//ULONG64 vmxBasic = __readmsr(IA32_VMX_BASIC);
	//*(PULONG)vmcs = (ULONG)vmxBasic;

	//设置当前VMCS
	if (__vmx_vmclear(&vcpu->vmcs_physical) != 0 || __vmx_vmptrld(&vcpu->vmcs_physical) != 0) {

		DbgPrintEx(77, 0, "[+]_vmx clear or vmx ptrld err\r\n");

		//执行相关清理操作
		
		return false;


	}

	//初始化vmcs的guest字段
	init_vmcs_guest(guest_rsp, guest_rip);
	//初始化vmcs的host字段
	init_vmcs_host(vcpu,vm_exit_handler);


	//初始化vm entry 控制
	init_vmcs_entry_controls();

	//初始化vm exit控制
	init_vmcs_exit_controls();

	//初始化vm executation 控制
	init_vmcs_vmexecute_controls(vcpu);



	
	return TRUE;
	


}

//确保VMX操作无误 调整控制寄存器
void adjust_control_registers(void)
{
	union __cr4_t cr4 = { 0 };
	union __cr0_t cr0 = { 0 };
	union __cr_fixed_t cr_fixed;
	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
	cr0.control = __readcr0();
	cr0.control |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
	cr0.control &= cr_fixed.split.low;
	__writecr0(cr0.control);
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
	cr4.control = __readcr4();
	cr4.control |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
	cr4.control &= cr_fixed.split.low;
	__writecr4(cr4.control);
}


//初始化逻辑处理器
void init_logical_processor(__vmm_context_t* context) {

	__vmm_context_t* vmm_context;
	__vcpu_t* vcpu;

	//获取guest rip rsp 即调用函数的rip 和之前的堆栈
	PULONG64 ret_addr = (PULONG64)_AddressOfReturnAddress();
	ULONG64 guest_rsp= (UINT64)(ret_addr +1);
	ULONG64 guest_rip = *ret_addr;
	//__vmx_misc_msr_t vmx_misc;

	unsigned long processor_number;

	processor_number = KeGetCurrentProcessorNumber();

	vmm_context = context;
	vcpu = vmm_context->vcpu_table[processor_number];

	DbgPrintEx(77,0,"[+]vcpu %d guest_rip 0x%llx guest_rsp 0x%llx\n", processor_number,guest_rip,guest_rsp);

	//调整控制寄存器
	adjust_control_registers();

	if (!init_vmxon(vcpu)) {

		DbgPrintEx(77, 0, "[+]failed to init vmxon\r\n");

		ExFreePool(context);

		return;
	}

	if (__vmx_on(&vcpu->vmxon_physical) != 0) {

		DbgPrintEx(77, 0, "[+]failed to put vcpu %d into VMX operation.\r\n", processor_number);
		ExFreePool(context);

		ExFreePool(vcpu);
		return;
	}

	
	DbgPrintEx(77, 0, "[+]cpu %d now in VMX operation\r\n", KeGetCurrentProcessorNumber());
	
	//初始化每个虚拟机cpu的vmcs vmlauch

	init_vmcs(vcpu, (void*)guest_rsp, (void (*)())guest_rip);
	
	//进行vmlaunch vm entry

	auto err_code = __vmx_vmlaunch();

	if (err_code)
	{
		DbgPrintEx(77, 0, "[+]vmlaunch err err code=0x%x\r\n", err_code);


		return;

	}

	return;
}


//初始化VMM
int vmm_init(unsigned long long vm_exit_handler) {

	struct __vmm_context_t* vmm_context;
	PROCESSOR_NUMBER processor_number{0};
	GROUP_AFFINITY affinity{ 0 }, old_affinity{0};
	
	
	vmm_context = allocate_vmm_context();

	//便于销毁
	gVmmContext = vmm_context;


	if (!vmm_context) {

		return false;

	}


	//设置vm exit handler 即host_rip
	vmm_context->vm_exit_handler = vm_exit_handler;

	for (int i = 0; i < vmm_context->processor_count; i++) {
		//填充vcpu上下文
		vmm_context->vcpu_table[i] = init_vcpu();
		vmm_context->vcpu_table[i]->vmm_context = vmm_context;


		//获取processor_number index->number;
		KeGetProcessorNumberFromIndex(i, &processor_number);
		

		affinity.Group = processor_number.Group;

		//用这个来表示处理器的亲和性掩码 可以唯一标识一个处理器 因此x64最多64个逻辑处理器
		affinity.Mask = (KAFFINITY)1 << processor_number.Number;

		KeSetSystemGroupAffinityThread(&affinity, &old_affinity);

		//初始化每个vCpu的上下文和vmcs
		init_logical_processor(vmm_context);

		//恢复亲和处理器
		KeRevertToUserGroupAffinityThread(&old_affinity);
	}

	

	return true;

}



void init_vmcs_host(__vcpu_t* vcpu, unsigned long long host_rip)
{

	
	//填充VMCS的Host区域
	GdtTable gdtTable{ 0 };
	asm_get_gdt_table(&gdtTable);

	unsigned short tr_register = asm_get_tr();

	unsigned short tr_seletor = tr_register & 0xfff8;


	unsigned long* tr_descriptor = (unsigned long*)(gdtTable.Base + tr_seletor);

	LARGE_INTEGER tr_base{ 0 };

	//IA-32E的TSS描述符是128位的 和LDT是一样的
	//取低32base
	//tr_base.LowPart = (((tr_descriptor[0] & 0xffff0000) >> 16) | ((tr_descriptor[1] & 0xff) << 16) | ((tr_descriptor[1]) & 0xff000000));
	//tr_base.HighPart = tr_descriptor[2];
	tr_base.LowPart = ((tr_descriptor[0] >> 16) & 0xFFFF) | ((tr_descriptor[1] & 0xFF) << 16) | ((tr_descriptor[1] & 0xFF000000));
	tr_base.HighPart = tr_descriptor[2];
	//fetch high 32 bits



	//属性
	__vmx_vmwrite(HOST_TR_BASE, tr_base.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, tr_seletor);

	//取得当前虚拟cpu的host栈
	__vmx_vmwrite(HOST_RSP, (size_t)vcpu->stack_base);
	__vmx_vmwrite(HOST_RIP, host_rip);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_CR3, __readcr3());

	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(IA32_MSR_EFER));
	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(IA32_MSR_PAT));

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	//Gdt idt
	GdtTable idtTable{ 0 };

	__sidt(&idtTable);

	__vmx_vmwrite(HOST_GDTR_BASE, gdtTable.Base);
	__vmx_vmwrite(HOST_IDTR_BASE, idtTable.Base);


	//host区域填充段寄存器
	__vmx_vmwrite(HOST_ES_SELECTOR, asm_get_es() & 0xfff8);
	__vmx_vmwrite(HOST_CS_SELECTOR, asm_get_cs() & 0xfff8);
	__vmx_vmwrite(HOST_SS_SELECTOR, asm_get_ss() & 0xfff8);
	__vmx_vmwrite(HOST_DS_SELECTOR, asm_get_ds() & 0xfff8);
	__vmx_vmwrite(HOST_FS_SELECTOR, asm_get_fs() & 0xfff8);
	__vmx_vmwrite(HOST_GS_SELECTOR, asm_get_gs() & 0xfff8);
 
}



void init_vmcs_guest(void* guest_rsp, void(*guest_rip)())
{

	

	//初始化段寄存器和属性填入VMCS
	full_vmcs_segemnt_atrributes(0, asm_get_es());
	full_vmcs_segemnt_atrributes(1, asm_get_cs());
	full_vmcs_segemnt_atrributes(2, asm_get_ss());
	full_vmcs_segemnt_atrributes(3, asm_get_ds());
	full_vmcs_segemnt_atrributes(4, asm_get_fs());
	full_vmcs_segemnt_atrributes(5, asm_get_gs());
	full_vmcs_segemnt_atrributes(6, asm_get_ldtr());
	


	//获取TR寄存器的基质和属性
	GdtTable gdtTable{ 0 };
	asm_get_gdt_table(&gdtTable);

	unsigned short tr_register = asm_get_tr();

	unsigned short tr_seletor = tr_register & 0xfff8;

	unsigned long tr_limit = __segmentlimit(tr_seletor);

	unsigned long* tr_descriptor = (unsigned long*)(gdtTable.Base + tr_seletor);

	LARGE_INTEGER tr_base{ 0 };

	//IA-32E的TSS描述符是128位的 和LDT是一样的
	//取低32base
	tr_base.LowPart = (((tr_descriptor[0] & 0xffff0000) >> 16) | ((tr_descriptor[1] & 0xff)<<16) | ((tr_descriptor[1]) & 0xff000000));

	//fetch high 32 bits

	tr_base.HighPart = tr_descriptor[2];

	unsigned long tr_attr = (tr_descriptor[1] & 0x00f0ff00) >> 8;

	__vmx_vmwrite(GUEST_TR_BASE, tr_base.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, tr_limit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, tr_attr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, tr_seletor);

	//写入其他寄存器
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));

	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_RIP, (size_t)guest_rip);
	__vmx_vmwrite(GUEST_RSP, (size_t)guest_rsp);
	 
	//VMCS链接指针 仅当在 VM 执行控制字段中启用 VMCS 阴影时才有用
	__vmx_vmwrite(VMCS_LINK_POINTER, (unsigned long long)-1);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_MSR_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(IA32_MSR_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(IA32_MSR_EFER));

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

	//填充IDT表和GDT表

	GdtTable idtTable{ 0 };
	__sidt(&idtTable);

	__vmx_vmwrite(GUEST_IDTR_BASE, idtTable.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtTable.limit);

	__vmx_vmwrite(GUEST_GDTR_BASE, gdtTable.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtTable.limit);



}

void init_vmcs_entry_controls()
{


	
	
	
	__vmx_entry_control_t entry{ 0 };
	__vmx_basic_msr_t basic_msr{ 0 };
	unsigned long entry_control_msr=0;

	basic_msr.control = __readmsr(IA32_VMX_BASIC_MSR);
	//VM Entry时保持IA32E模式
	entry.bits.ia32e_mode_guest = true;

	//根据baisc位决定用哪个entry控制寄存器
	entry_control_msr = (basic_msr.bits.true_controls) ? IA32_MSR_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

	//读取此MSR寄存器的值
	entry.control = vmx_adjust_entry_control(entry.control, entry_control_msr);

	__vmx_vmwrite(VM_ENTRY_CONTROLS, entry.control);


	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

}

void init_vmcs_exit_controls()
{


	__vmx_exit_control_t exit_control{0};
	unsigned exit_control_msr = 0;
	__vmx_basic_msr_t basic_msr{0};
	//vm exit确保是x64模式
	exit_control.bits.host_address_space_size = true;

	//这个代表vm exit是否中断 1代表中断
	exit_control.bits.ack_interrupt_on_exit=true;

	basic_msr.control = __readmsr(IA32_VMX_BASIC_MSR);

	exit_control_msr = (basic_msr.bits.true_controls) ? IA32_MSR_VMX_TRUE_EXIT_CTLS : IA32_MSR_VMX_EXIT_CTLS;;

	exit_control.control = vmx_adjust_entry_control(exit_control.control, exit_control_msr);

	//写入VM Exit
	__vmx_vmwrite(VM_EXIT_CONTROLS, exit_control.control);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_INTR_INFO, 0);

}

bool vmx_set_msr_bitmap(PUCHAR msr_bitmap, UINT64 msr_index, bool isread, bool isenable) {

	ULONG64 uMoveBytes = 0;
	unsigned char Bits=0;

	//处理底/高Msr
	if (msr_index >= 0xC0000000) {

		uMoveBytes = 0x400;
		msr_index -= 0xC0000000;
	}

	if (!isread) {
	   //写的话从0x800开始

		uMoveBytes += 0x800;
	
	}

	//取得移动的步长的第几位
	uMoveBytes += msr_index / 8;
	Bits = msr_index % 8;

	if (isenable) {

		*(msr_bitmap + uMoveBytes) |= (1 << Bits);

	}
	else {

		*(msr_bitmap + uMoveBytes) &= ~(1 << Bits);
	}


	return true;

}

BOOLEAN VmxSetReadMsrBitMap(PUCHAR msrBitMap, ULONG64 msrAddrIndex, BOOLEAN isEnable)
{
	if (msrAddrIndex >= 0xC0000000)
	{
		msrBitMap += 1024;
		msrAddrIndex -= 0xC0000000;
	}

	ULONG64 moveByte = 0;
	ULONG64 setBit = 0;

	if (msrAddrIndex != 0)
	{
		moveByte = msrAddrIndex / 8;

		setBit = msrAddrIndex % 8;

		msrBitMap += moveByte;
	}

	if (isEnable)
	{
		*msrBitMap |= 1 << setBit;
	}
	else
	{
		*msrBitMap &= ~(1 << setBit);
	}

	return TRUE;

}

BOOLEAN VmxSetWriteMsrBitMap(PUCHAR msrBitMap, ULONG64 msrAddrIndex, BOOLEAN isEnable)
{
	msrBitMap += 0x800;

	return VmxSetReadMsrBitMap(msrBitMap, msrAddrIndex, isEnable);

}


void init_vmcs_vmexecute_controls(__vcpu_t* vcpu)
{
	

	__vmx_basic_msr_t basic_msr{ 0 };
	__vmx_pinbased_control_msr_t pinbased_control { 0 };
	__vmx_primary_processor_based_control_t primary_processor_based_control{ 0 };
	__vmx_secondary_processor_based_control_t second_processor_based_control{ 0 };

	unsigned long pinbase_msr, primary_processor_msr, second_processor_msr;


	basic_msr.control = __readmsr(IA32_VMX_BASIC_MSR);

	//确定pinbase的msr
	pinbase_msr = (basic_msr.bits.true_controls) ? IA32_MSR_VMX_TRUE_PINBASED_CTLS : IA32_MSR_VMX_PINBASED_CTLS;

	//pinbase和中断有关,这里不涉及,不修改此MSR
	pinbased_control.control = vmx_adjust_entry_control(0, pinbase_msr);

	//确定primary control的msr
	primary_processor_msr = (basic_msr.bits.true_controls) ? IA32_MSR_VMX_TRUE_PROCBASED_CTLS : IA32_MSR_VMX_PROCBASED_CTLS;;

	//使用msr位图以及使用副cpu控制
	primary_processor_based_control.bits.active_secondary_controls = true;
	primary_processor_based_control.bits.use_msr_bitmaps = true;

	//不修改
	primary_processor_based_control.control = vmx_adjust_entry_control(primary_processor_based_control.control, primary_processor_msr);

	
	//vcpu已经分配了msr位图

	__vmx_vmwrite(MSR_BITMAP, vcpu->msr_bitmap_physical);

	////设置位图
	//VmxSetReadMsrBitMap((PUCHAR)vcpu->msr_bitmap, 0xc0000082, TRUE);
	//VmxSetWriteMsrBitMap((PUCHAR)vcpu->msr_bitmap, 0xc0000082, TRUE);
	vmx_set_msr_bitmap((PUCHAR)vcpu->msr_bitmap, 0xc0000082, true, true);

	vmx_set_msr_bitmap((PUCHAR)vcpu->msr_bitmap, 0xc0000082, false, true);
	
	//ULONG number = KeGetCurrentProcessorNumberEx(NULL);
	//__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, number + 1);

	//__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	//__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	//__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	//__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	//__vmx_vmwrite(CR3_TARGET_VALUE3, 0);

	//复CPU控制 需要修改
	second_processor_msr = IA32_MSR_VMX_PROCBASED_CTLS2;


	//这些win10需要用到
	second_processor_based_control.bits.enable_rdtscp = true;
	second_processor_based_control.bits.enable_xsave_xrstor = true;
	second_processor_based_control.bits.enable_invpcid = true;

	second_processor_based_control.control = vmx_adjust_entry_control(second_processor_based_control.control, second_processor_msr);

	//写入
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pinbased_control.control);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary_processor_based_control.control);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, second_processor_based_control.control);

}

unsigned long long vmx_adjust_entry_control(unsigned int vaule,unsigned int msr) {

	__vmx_true_control_settings_t cap;

	unsigned int actual;

	cap.control = __readmsr(msr);

	actual = vaule;

	actual |= cap.allowed_0_settings;
	actual &= cap.allowed_1_settings;

	return actual;

}

void full_vmcs_segemnt_atrributes(unsigned int index,short selector) {

	//根据索引 填充VMCS的段属性

	GdtTable gdtTable{ 0 };
	LARGE_INTEGER item_base{0};

	asm_get_gdt_table(&gdtTable);

	selector &= 0xfff8;

	//获取段界限和段描述符表地址
	unsigned long limit = __segmentlimit(selector);
	unsigned long* item = (unsigned long*)(gdtTable.Base + selector);

	//获取段基质 这一步是为了兼容32位 因为32位可能不是平坦模式
	item_base.LowPart = (*item & 0xFFFF0000) >> 16;
	item += 1;
	item_base.LowPart |= (*item & 0xFF000000) | ((*item & 0xFF) << 16);

	//获取段描述符的属性
	unsigned long attribute = (*item & 0x00f0ff00) >> 8;

	if (selector == 0)
	{
		attribute |= 1 << 16;
	}

	//写入
	__vmx_vmwrite(GUEST_ES_BASE + index * 2, item_base.QuadPart);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attribute);
	__vmx_vmwrite(GUEST_ES_SELECTOR+index*2, selector);


}