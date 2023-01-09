#pragma once

#define IA32_FEATURE_CONTROL  0x3A
#define VMM_TAG 'VmmT'
#define VMM_STACK_SIZE 0x6000
#define IA32_VMX_BASIC_MSR 0x480
#define IA32_VMX_CR0_FIXED0						0x486
#define IA32_VMX_CR0_FIXED1						0x487
#define IA32_VMX_CR4_FIXED0						0x488
#define IA32_VMX_CR4_FIXED1						0x489
struct __vmm_context_t {

	int processor_count;
	void* stack;
	struct __vcpu_t** vcpu_table;

	//vm exit handler
	unsigned long long vm_exit_handler;
};

struct __vmcs_t
{
	union
	{
		unsigned int all;
		struct
		{
			unsigned int revision_identifier : 31;
			unsigned int shadow_vmcs_indicator : 1;
		} bits;
	} header;

	unsigned int abort_indicator;
	char data[0x1000 - 2 * sizeof(unsigned)];
};

struct __vcpu_t
{
	struct __vmcs_t* vmcs;
	unsigned __int64 vmcs_physical;

	struct __vmcs_t* vmxon; //vmxon区域和vmcs定义一样
	unsigned __int64 vmxon_physical;

	//反向链接
	struct __vmm_context_t* vmm_context;

	//msr 位图 用于控制W/R那些MSR寄存器会导致VM Exit
	//用于初始化VMCS时提供的MSR位图物理地址
	//同样 有用VA PA
	void* msr_bitmap;
	unsigned __int64 msr_bitmap_physical;

	//stack
	void* stack_base;
	void* stack_top;
};

struct _ECX
{
	unsigned SSE3 : 1;        //SSE3指令集
	unsigned PCLMULQDQ : 1;   //Carry-Less Multiplication
	unsigned DTES64 : 1;      //64 位浮点指令集
	unsigned MONITOR : 1;     //MONITOR 和 MWAIT 指令
	unsigned DS_CPL : 1;      //CPL 时钟控制
	unsigned VMX : 1;         //虚拟化技术
	unsigned SMX : 1;         //安全虚拟化
	unsigned EST : 1;         //频率估计
	unsigned TM2 : 1;         //温度传感器
	unsigned SSSE3 : 1;       //Supplemental SSE3
	unsigned CID : 1;         //L1 地址容错
	unsigned SDBG : 1;        //调试指令
	unsigned FMA : 1;         //FMA 指令
	unsigned CX16 : 1;        //CMPXCHG16B 指令
	unsigned XTPR : 1;        //可扩展的中断定时器
	unsigned PDCM : 1;        //监控指令
	unsigned PCID : 1;        //PCID 指令
	unsigned DCA : 1;         //直接缓存访问
	unsigned SSE4_1 : 1;      //SSE4.1 指令
	unsigned SSE4_2 : 1;      //SSE4.2 指令
	unsigned X2APIC : 1;      //X2APIC 指令
	unsigned MOVBE : 1;       //MOVBE 指令
	unsigned POPCNT : 1;      //POPCNT 指令
	unsigned TSC_DEADLINE : 1;//TSC 在线指令
	unsigned AES : 1;         //AES 指令
	unsigned XSAVE : 1;       //XSAVE/XRSTOR 指令
	unsigned OSXSAVE : 1;     //XSAVE 支持
	unsigned AVX : 1;         //AVX 指令
	unsigned F16C : 1;        //16 位浮点指令集
	unsigned RDRAND : 1;      //RDRAND 指令
	unsigned Reserved : 16;   //保留
};


typedef struct _cpuinfo {

	int Eax;
	int Ebx;
	union  {
		_ECX Bits;
		int all;
	}Ecx;
	

	int Edx;



}cpuinfo, * pcpuinfo;

union __cr4_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 vme : 1;									 // bit 0
		unsigned __int64 pvi : 1;									 // bit 1
		unsigned __int64 time_stamp_disable : 1;					 // bit 2
		unsigned __int64 debug_extensions : 1;						 // bit 3
		unsigned __int64 page_size_extension : 1;					 // bit 4
		unsigned __int64 physical_address_extension : 1;			 // bit 5
		unsigned __int64 machine_check_enable : 1;					 // bit 6
		unsigned __int64 page_global_enable : 1;					 // bit 7
		unsigned __int64 perf_counter_enable : 1;					 // bit 8
		unsigned __int64 os_fxsave_support : 1;						 // bit 9
		unsigned __int64 os_xmm_exception_support : 1;				 // bit 10
		unsigned __int64 usermode_execution_prevention : 1;			 // bit 11
		unsigned __int64 reserved_0 : 1;							 // bit 12
		unsigned __int64 vmx_enable : 1;							 // bit 13
		unsigned __int64 smx_enable : 1;							 // bit 14
		unsigned __int64 reserved_1 : 1;							 // bit 15
		unsigned __int64 fs_gs_enable : 1;							 // bit 16
		unsigned __int64 pcide : 1;									 // bit 17
		unsigned __int64 os_xsave : 1;								 // bit 18
		unsigned __int64 reserved_2 : 1;							 // bit 19
		unsigned __int64 smep : 1;									 // bit 20
		unsigned __int64 smap : 1;									 // bit 21
		unsigned __int64 protection_key_enable : 1;					 // bit 22
	} bits;
};

union __ia32_feature_control_msr_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 lock : 1;
		unsigned __int64 vmxon_inside_smx : 1;
		unsigned __int64 vmxon_outside_smx : 1;
		unsigned __int64 reserved_0 : 5;
		unsigned __int64 senter_local : 6;
		unsigned __int64 senter_global : 1;
		unsigned __int64 reserved_1 : 1;
		unsigned __int64 sgx_launch_control_enable : 1;
		unsigned __int64 sgx_global_enable : 1;
		unsigned __int64 reserved_2 : 1;
		unsigned __int64 lmce : 1;
		unsigned __int64 system_reserved : 42;
	} bits;
};


union __vmx_basic_msr_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 vmcs_revision_identifier : 31;
		unsigned __int64 always_0 : 1;
		unsigned __int64 vmxon_region_size : 13;
		unsigned __int64 reserved_1 : 3;
		unsigned __int64 vmxon_physical_address_width : 1;
		unsigned __int64 dual_monitor_smi : 1;
		unsigned __int64 memory_type : 4;
		unsigned __int64 io_instruction_reporting : 1;
		unsigned __int64 true_controls : 1;
	} bits;
};
union __cr0_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 protection_enable : 1;
		unsigned __int64 monitor_coprocessor : 1;
		unsigned __int64 emulate_fpu : 1;
		unsigned __int64 task_switched : 1;
		unsigned __int64 extension_type : 1;
		unsigned __int64 numeric_error : 1;
		unsigned __int64 reserved_0 : 10;
		unsigned __int64 write_protection : 1;
		unsigned __int64 reserved_1 : 1;
		unsigned __int64 alignment_mask : 1;
		unsigned __int64 reserved_2 : 10;
		unsigned __int64 not_write_through : 1;
		unsigned __int64 cache_disable : 1;
		unsigned __int64 paging_disable : 1;
	} bits;
};

union __vmx_misc_msr_t
{
	unsigned __int64 control;
	struct
	{
		unsigned __int64 vmx_preemption_tsc_rate : 5;
		unsigned __int64 store_lma_in_vmentry_control : 1;
		unsigned __int64 activate_state_bitmap : 3;
		unsigned __int64 reserved_0 : 5;
		unsigned __int64 pt_in_vmx : 1;
		unsigned __int64 rdmsr_in_smm : 1;
		unsigned __int64 cr3_target_value_count : 9;
		unsigned __int64 max_msr_vmexit : 3;
		unsigned __int64 allow_smi_blocking : 1;
		unsigned __int64 vmwrite_to_any : 1;
		unsigned __int64 interrupt_mod : 1;
		unsigned __int64 reserved_1 : 1;
		unsigned __int64 mseg_revision_identifier : 32;
	} bits;
};

union __cr_fixed_t
{
	struct
	{
		unsigned long low;
		long high;
	} split;
	struct
	{
		unsigned long low;
		long high;
	} u;
	long long all;
};