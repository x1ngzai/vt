#pragma once
#include "stdafx.h"

/*
* Intel CPU  MSR
*/
/* MSRs & bits used for VMX enabling */

#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING		        0x00008000
#define CPU_BASED_CR3_STORE_EXITING		       0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING		     0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MTF_TRAP_EXITING              0x08000000
#define CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR	0x00000016
#define VM_EXIT_SAVE_DEBUG_CONTROLS      0x00000004
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_IA32_PAT			0x00040000
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_SAVE_IA32_EFER          0x00100000
#define VM_EXIT_LOAD_IA32_EFER          0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000

#define VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_IA32_PAT			0x00004000
#define VM_ENTRY_LOAD_IA32_EFER         0x00008000
#define VM_ENTRY_LOAD_BNDCFGS           0x00010000

#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9


#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */


#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MACHINE_CHECK       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define  EXIT_REASON_RDTSCP 51

/* VMCS Encordings */
enum
{
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NV = 0x00000002,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_A_HIGH = 0x00002001,
	IO_BITMAP_B = 0x00002002,
	IO_BITMAP_B_HIGH = 0x00002003,
	MSR_BITMAP = 0x00002004,
	MSR_BITMAP_HIGH = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	TSC_OFFSET = 0x00002010,
	TSC_OFFSET_HIGH = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	APIC_ACCESS_ADDR = 0x00002014,
	APIC_ACCESS_ADDR_HIGH = 0x00002015,
	POSTED_INTR_DESC_ADDR = 0x00002016,
	POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
	EPT_POINTER = 0x0000201a,
	EPT_POINTER_HIGH = 0x0000201b,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
	EOI_EXIT_BITMAP1 = 0x0000201e,
	EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
	EOI_EXIT_BITMAP2 = 0x00002020,
	EOI_EXIT_BITMAP2_HIGH = 0x00002021,
	EOI_EXIT_BITMAP3 = 0x00002022,
	EOI_EXIT_BITMAP3_HIGH = 0x00002023,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	XSS_EXIT_BITMAP = 0x0000202C,
	XSS_EXIT_BITMAP_HIGH = 0x0000202D,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,
	VMCS_LINK_POINTER_HIGH = 0x00002801,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	GUEST_IA32_PAT = 0x00002804,
	GUEST_IA32_PAT_HIGH = 0x00002805,
	GUEST_IA32_EFER = 0x00002806,
	GUEST_IA32_EFER_HIGH = 0x00002807,
	GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
	GUEST_PDPTR0 = 0x0000280a,
	GUEST_PDPTR0_HIGH = 0x0000280b,
	GUEST_PDPTR1 = 0x0000280c,
	GUEST_PDPTR1_HIGH = 0x0000280d,
	GUEST_PDPTR2 = 0x0000280e,
	GUEST_PDPTR2_HIGH = 0x0000280f,
	GUEST_PDPTR3 = 0x00002810,
	GUEST_PDPTR3_HIGH = 0x00002811,
	GUEST_BNDCFGS = 0x00002812,
	GUEST_BNDCFGS_HIGH = 0x00002813,
	HOST_IA32_PAT = 0x00002c00,
	HOST_IA32_PAT_HIGH = 0x00002c01,
	HOST_IA32_EFER = 0x00002c02,
	HOST_IA32_EFER_HIGH = 0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO_FIELD = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0X00004826,
	GUEST_SYSENTER_CS = 0x0000482A,
	VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
	HOST_IA32_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	CR3_TARGET_VALUE1 = 0x0000600a,
	CR3_TARGET_VALUE2 = 0x0000600c,
	CR3_TARGET_VALUE3 = 0x0000600e,
	EXIT_QUALIFICATION = 0x00006400,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP = 0x00006c10,
	HOST_IA32_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};


#define KGDT64_R0_DATA ((1*16)+8)
#define KGDT64_R0_CODE (1*16)



typedef struct _VMX_CPU
{
	PVOID pVMXONRegion;
	PHYSICAL_ADDRESS pVMXONRegion_PA;
	PVOID pVMCSRegion;
	PHYSICAL_ADDRESS pVMCSRegion_PA;
	PVOID pHostEsp;

	BOOLEAN bVTStartSuccess;
}VMX_CPU, *PVMX_CPU;




/////////////////////////////////////////


typedef union
{
	struct
	{
		unsigned PE : 1;
		unsigned MP : 1;
		unsigned EM : 1;
		unsigned TS : 1;
		unsigned ET : 1;
		unsigned NE : 1;
		unsigned Reserved_1 : 10;
		unsigned WP : 1;
		unsigned Reserved_2 : 1;
		unsigned AM : 1;
		unsigned Reserved_3 : 10;
		unsigned NW : 1;
		unsigned CD : 1;
		unsigned PG : 1;
		unsigned Reserved_64 : 32;
	};

}_CR0;

typedef union
{
	struct {
		unsigned VME : 1;
		unsigned PVI : 1;
		unsigned TSD : 1;
		unsigned DE : 1;
		unsigned PSE : 1;
		unsigned PAE : 1;
		unsigned MCE : 1;
		unsigned PGE : 1;
		unsigned PCE : 1;
		unsigned OSFXSR : 1;
		unsigned PSXMMEXCPT : 1;
		unsigned UNKONOWN_1 : 1;		//These are zero
		unsigned UNKONOWN_2 : 1;		//These are zero
		unsigned VMXE : 1;			//It's zero in normal
		unsigned Reserved : 18;		//These are zero
		unsigned Reserved_64 : 32;
	};
}_CR4;

typedef union
{
	struct
	{
		unsigned CF : 1;
		unsigned Unknown_1 : 1;	//Always 1
		unsigned PF : 1;
		unsigned Unknown_2 : 1;	//Always 0
		unsigned AF : 1;
		unsigned Unknown_3 : 1;	//Always 0
		unsigned ZF : 1;
		unsigned SF : 1;
		unsigned TF : 1;
		unsigned IF : 1;
		unsigned DF : 1;
		unsigned OF : 1;
		unsigned TOPL : 2;
		unsigned NT : 1;
		unsigned Unknown_4 : 1;
		unsigned RF : 1;
		unsigned VM : 1;
		unsigned AC : 1;
		unsigned VIF : 1;
		unsigned VIP : 1;
		unsigned ID : 1;
		unsigned Reserved : 10;	//Always 0
		unsigned Reserved_64 : 32;	//Always 0
	};
}_EFLAGS;

typedef union
{
	struct
	{
		unsigned SSE3 : 1;
		unsigned PCLMULQDQ : 1;
		unsigned DTES64 : 1;
		unsigned MONITOR : 1;
		unsigned DS_CPL : 1;
		unsigned VMX : 1;
		unsigned SMX : 1;
		unsigned EIST : 1;
		unsigned TM2 : 1;
		unsigned SSSE3 : 1;
		unsigned Reserved : 22;
		unsigned Reserved_64 : 32;
	};

}_CPUID_ECX;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock : 1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1 : 1;		// Undefined
	unsigned EnableVmxon : 1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2 : 29;	// Undefined
	unsigned Reserved3 : 32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

typedef struct _VMX_BASIC_MSR
{
	unsigned RevId : 32;//版本号信息
	unsigned szVmxOnRegion : 12;
	unsigned ClearBit : 1;
	unsigned Reserved : 3;
	unsigned PhysicalWidth : 1;
	unsigned DualMonitor : 1;
	unsigned MemoryType : 4;
	unsigned VmExitInformation : 1;
	unsigned Reserved2 : 9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;





//////////////////////////
#define LA_ACCESSED		0x01
#define LA_READABLE		0x02    // for code segments
#define LA_WRITABLE		0x02    // for data segments
#define LA_CONFORMING	0x04    // for code segments
#define LA_EXPANDDOWN	0x04    // for data segments
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

#define LA_LDT64		0x02
#define LA_ATSS64		0x09
#define LA_BTSS64		0x0b
#define LA_CALLGATE64	0x0c
#define LA_INTGATE64	0x0e
#define LA_TRAPGATE64	0x0f

#define HA_AVAILABLE	0x01
#define HA_LONG			0x02
#define HA_DB			0x04
#define HA_GRANULARITY	0x08

#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100

#define	PML4_BASE	0xFFFFF6FB7DBED000 //和windows内核的四个常量对应
#define	PDP_BASE	0xFFFFF6FB7DA00000 //#define PXE_BASE 0xFFFFF6FB7DBED000UI64
#define	PD_BASE		0xFFFFF6FB40000000 //#define PPE_BASE 0xFFFFF6FB7DA00000UI64
#define	PT_BASE		0xFFFFF68000000000 //#define PDE_BASE 0xFFFFF6FB40000000UI64
//#define PTE_BASE 0xFFFFF68000000000UI64

#define ITL_TAG	'LTI'

#define BP_GDT_LIMIT	0x6f
#define BP_IDT_LIMIT	0xfff
#define BP_TSS_LIMIT	0x68    // 0x67 min

#define BP_GDT_LIMIT	0x6f
#define BP_IDT_LIMIT	0xfff
#define BP_TSS_LIMIT	0x68    // 0x67 min


#define TRAP_MTF						0
#define TRAP_DEBUG						1
#define TRAP_INT3						3
#define TRAP_INTO						4
#define TRAP_GP					    13
#define TRAP_PAGE_FAULT					14
#define TRAP_INVALID_OP					6

/*
* Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
* segment descriptor.
*/


typedef union
{
	USHORT UCHARs;
	struct
	{
		USHORT type : 4;              /* 0;  Bit 40-43 */
		USHORT s : 1;                 /* 4;  Bit 44 */
		USHORT dpl : 2;               /* 5;  Bit 45-46 */
		USHORT p : 1;                 /* 7;  Bit 47 */
									  // gap!       
		USHORT avl : 1;               /* 8;  Bit 52 */
		USHORT l : 1;                 /* 9;  Bit 53 */
		USHORT db : 1;                /* 10; Bit 54 */
		USHORT g : 1;                 /* 11; Bit 55 */
		USHORT Gap : 4;
	} fields;
} SEGMENT_ATTRIBUTES;

typedef struct _SEGMENT_SELECTOR
{
	USHORT sel;
	SEGMENT_ATTRIBUTES attributes;
	ULONG limit;
	ULONG64 base;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT limit0;
	USHORT base0;
	UCHAR base1;
	UCHAR attr0;
	UCHAR limit1attr1;
	UCHAR base2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _TSS64
{
	ULONG Reserved0;
	PVOID RSP0;
	PVOID RSP1;
	PVOID RSP2;
	ULONG64 Reserved1;
	PVOID IST1;
	PVOID IST2;
	PVOID IST3;
	PVOID IST4;
	PVOID IST5;
	PVOID IST6;
	PVOID IST7;
	ULONG64 Reserved2;
	USHORT Reserved3;
	USHORT IOMapBaseAddress;
} TSS64,
*PTSS64;

typedef struct	_SEG_DESCRIPTOR
{
	unsigned	LimitLo : 16;
	unsigned	BaseLo : 16;
	unsigned	BaseMid : 8;
	unsigned	Type : 4;
	unsigned	System : 1;
	unsigned	DPL : 2;
	unsigned	Present : 1;
	unsigned	LimitHi : 4;
	unsigned	AVL : 1;
	unsigned	L : 1;
	unsigned	DB : 1;
	unsigned	Gran : 1;		// Granularity
	unsigned	BaseHi : 8;

} SEG_DESCRIPTOR;



typedef struct _DEBUG_DR6_
{

	unsigned B0 : 1;//Dr0断点访问
	unsigned B1 : 1;//Dr1断点访问
	unsigned B2 : 1;//Dr2断点访问
	unsigned B3 : 1;//Dr3断点访问
	unsigned Reverted : 9;
	unsigned BD : 1;//有DEBUG寄存器访问引发的#DB异常
	unsigned BS : 1;//有单步引发的#DB异常
	unsigned BT : 1;//有TASK switch 任务切换引发的#DB异常
	unsigned Reverted2 : 16;

}DEBUG_DR6, *PDEBUG_DR6;

typedef struct _DEBUG_DR7_
{

	unsigned L0 : 1; //0 DR0断点#DB
	unsigned G0 : 1; //1
	unsigned L1 : 1; //2 DR1断点#DB
	unsigned G1 : 1; //3
	unsigned L2 : 1; //4 DR2断点#DB
	unsigned G2 : 1; //5
	unsigned L3 : 1; //6 DR3断点#DB
	unsigned G3 : 1; //7
	unsigned LE : 1; //8
	unsigned GE : 1; //9
	unsigned reserved : 3; //001  //10-11-12
	unsigned GD : 1; //13...允许对DEBUG寄存器访问产生#DB异常
	unsigned reserved2 : 2; //00
	unsigned RW0 : 2;//设置DR0访问类型 00B执行断点 01B写断点 10B IO读/写断点11B 读/写断点
	unsigned LEN0 : 2;//设置DR0字节长度 00B一个字节 01B WORD 10B QWORD 11B DWORD 
	unsigned RW1 : 2;//设置DR1访问类型
	unsigned LEN1 : 2;//设置DR1字节长度
	unsigned RW2 : 2;//设置DR2访问类型
	unsigned LEN2 : 2;//设置DR2字节长度
	unsigned RW3 : 2;//设置DR3访问类型
	unsigned LEN3 : 2;//设置DR3字节长度

}DEBUG_DR7, *PDEBUG_DR7;

typedef struct _INTERRUPT_INJECT_INFO_FIELD {
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned DeliverErrorCode : 1;
	unsigned Reserved : 19;
	unsigned Valid : 1;
} INTERRUPT_INJECT_INFO_FIELD, *PINTERRUPT_INJECT_INFO_FIELD;

typedef struct _INTERRUPT_IBILITY_INFO {
	unsigned STI : 1;
	unsigned MOV_SS : 1;
	unsigned SMI : 1;
	unsigned NMI : 1;
	unsigned Reserved : 27;
} INTERRUPT_IBILITY_INFO, *PINTERRUPT_IBILITY_INFO;


#define DIVIDE_ERROR_EXCEPTION 0
#define DEBUG_EXCEPTION 1
#define NMI_INTERRUPT 2
#define BREAKPOINT_EXCEPTION 3
#define OVERFLOW_EXCEPTION 4
#define BOUND_EXCEPTION 5
#define INVALID_OPCODE_EXCEPTION 6
#define DEVICE_NOT_AVAILABLE_EXCEPTION 7
#define DOUBLE_FAULT_EXCEPTION 8
#define COPROCESSOR_SEGMENT_OVERRUN 9
#define INVALID_TSS_EXCEPTION 10
#define SEGMENT_NOT_PRESENT 11
#define STACK_FAULT_EXCEPTION 12
#define GENERAL_PROTECTION_EXCEPTION 13
#define PAGE_FAULT_EXCEPTION 14
#define X87_FLOATING_POINT_ERROR 16
#define ALIGNMENT_CHECK_EXCEPTION 17
//#define MACHINE_CHECK_EXCEPTION 18
#define SIMD_FLOATING_POINT_EXCEPTION 19

#define EXTERNAL_INTERRUPT 0
#define HARDWARE_EXCEPTION 3
#define SOFTWARE_INTERRUPT 4
#define PRIVILEGED_SOFTWARE_EXCEPTION 5
#define SOFTWARE_EXCEPTION 6
#define OTHER_EVENT 7

typedef struct _INTERRUPT_INFO_FIELD {
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned ErrorCodeValid : 1;
	unsigned NMIUnblocking : 1;
	unsigned Reserved : 18;
	unsigned Valid : 1;
} INTERRUPT_INFO_FIELD, *PINTERRUPT_INFO_FIELD;

typedef struct
{
	USHORT limit0;
	USHORT base0;
	UCHAR  base1;
	UCHAR  attr0;
	UCHAR  limit1attr1;
	UCHAR  base2;
} SEGMENT_DESCRIPTOR2, *PSEGMENT_DESCRIPTOR2;
///////////////////
EXTERN_C NTSTATUS StartVT();
EXTERN_C NTSTATUS StopVT();
//////////////////


