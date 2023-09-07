
#include "startvt.h"
#include "vmmentry.h"
#include "vtasm.h"
KMUTEX g_GlobalMutex;
VMX_CPU g_VMXCPU[128];



enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};




NTSTATUS AllocateVMXRegion()
{
	PVOID pVMXONRegion;
	PVOID pVMCSRegion;
	PVOID pHostEsp;
	ULONG64 uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();
	pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmon'); //4KB
	if (!pVMXONRegion)
	{
		Log("ERROR:����VMXON�ڴ�����ʧ��!", 0);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMXONRegion, 0x1000);

	pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmcs');
	if (!pVMCSRegion)
	{
		Log("ERROR:����VMCS�ڴ�����ʧ��!", 0);
		ExFreePoolWithTag(pVMXONRegion, 0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMCSRegion, 0x1000);

	pHostEsp = ExAllocatePoolWithTag(NonPagedPool, 0x2000, 'mini');
	if (!pHostEsp)
	{
		Log("ERROR:������������������ʧ��!", 0);
		ExFreePoolWithTag(pVMXONRegion, 0x1000);
		ExFreePoolWithTag(pVMCSRegion, 0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pHostEsp, 0x2000);

	Log("TIP:VMXON�ڴ������ַ", pVMXONRegion);
	Log("TIP:VMCS�ڴ������ַ", pVMCSRegion);
	Log("TIP:���������������ַ", pHostEsp);

	g_VMXCPU[uCPUID].pVMXONRegion = pVMXONRegion;
	g_VMXCPU[uCPUID].pVMXONRegion_PA = MmGetPhysicalAddress(pVMXONRegion);
	g_VMXCPU[uCPUID].pVMCSRegion = pVMCSRegion;
	g_VMXCPU[uCPUID].pVMCSRegion_PA = MmGetPhysicalAddress(pVMCSRegion);
	g_VMXCPU[uCPUID].pHostEsp = pHostEsp;
	return STATUS_SUCCESS;
}
NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, ULONG64 GdtBase)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;

	if (!SegmentSelector)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//
	// �����ѡ���ӵ�T1 = 1��ʾ����LDT�е���, ����û��ʵ���������
	//
	if (Selector & 0x4)
	{

		return STATUS_INVALID_PARAMETER;
	}

	//
	// ��GDT��ȡ��ԭʼ�Ķ�������
	//
	SegDesc = (PSEGMENT_DESCRIPTOR2)((PUCHAR)GdtBase + (Selector & ~0x7));

	//
	// ��ѡ����
	//
	SegmentSelector->sel = Selector;

	//
	// �λ�ַ15-39λ 55-63λ
	//
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;

	//
	// ���޳�0-15λ  47-51λ, ������ȡ��
	//
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;

	//
	// ������39-47 51-55 ע��۲�ȡ��
	//
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	//
	// �����ж����Ե�DTλ, �ж��Ƿ���ϵͳ�����������Ǵ������ݶ�������
	//
	if (!(SegDesc->attr0 & LA_STANDARD))
	{
		ULONG64 tmp;

		//
		// �����ʾ��ϵͳ��������������������, �о�����Ϊ64λ׼���İ�,
		// 32λ����λ�ַֻ��32λ��. �ѵ�64λ������ʲô������?
		//
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));

		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	//
	// ���Ƕν��޵�����λ, 1Ϊ4K. 0Ϊ1BYTE
	//
	if (SegmentSelector->attributes.fields.g)
	{
		//
		// �������λΪ1, ��ô�ͳ���4K. ���ƶ�12λ
		//
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}
NTSTATUS FillGuestSelectorData(ULONG64 GdtBase, ULONG Segreg, USHORT
	Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)& SegmentSelector.attributes)[0] + (((PUCHAR)&
		SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	Vmx_VmWrite(GUEST_ES_SELECTOR + Segreg * 2, Selector & 0xFFF8);
	Vmx_VmWrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);
	Vmx_VmWrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
	Vmx_VmWrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
	// 	if ((Segreg == LDTR) || (Segreg == TR))
	// 		// don't setup for FS/GS - their bases are stored in MSR values
	// 		Vmx_VmWrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

	return STATUS_SUCCESS;
}
BOOLEAN IsVTEnabled()
{
	ULONG64  uRet_EAX, uRet_EBX, uRet_ECX, uRet_EDX ;
	_CPUID_ECX uCPUID;
	_CR0 uCr0;
	_CR4 uCr4;
	IA32_FEATURE_CONTROL_MSR msr;
	//1. CPUID
	 _CPUID(1,&uRet_EAX, &uRet_EBX, &uRet_ECX, &uRet_EDX);
	
	/*_asm
	{
		xor rax,rax
		mov eax,1
		cpuid
		mov qword ptr[uRet_ECX],rcx
	}*/
	*((PULONG64)&uCPUID) = uRet_ECX;
	if (uCPUID.VMX != 1)
	{
		Log("ERROR:���CPU��֧��VT!", 0);
		return FALSE;
	}

	// 2. CR0 CR4
	*((PULONG64)&uCr0) = GetCr0();
	*((PULONG64)&uCr4) = GetCr4();

	if (uCr0.PE != 1 || uCr0.PG != 1 || uCr0.NE != 1)
	{
		Log("ERROR:���CPUû�п���VT!", 0);
		return FALSE;
	}

	if (uCr4.VMXE == 1)
	{
		Log("ERROR:���CPU�Ѿ�������VT!", 0);
		Log("�����Ǳ�������Ѿ�ռ����VT�������ر�������ܿ�����", 0);
		return FALSE;
	}
	// 3. MSR
	*((PULONG64)&msr) = ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock != 1)
	{
		Log("ERROR:VTָ��δ������!", 0);
		return FALSE;
	}
	Log("SUCCESS:���CPU֧��VT!", 0);
	return TRUE;
}
void SetupVMXRegion()
{
	VMX_BASIC_MSR Msr;
	ULONG uRevId;
	_CR4 uCr4;
	_EFLAGS uEflags;
	ULONG64 uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();

	RtlZeroMemory(&Msr, sizeof(Msr));

	*((PULONG64)&Msr) = ReadMsr(MSR_IA32_VMX_BASIC);
	uRevId = Msr.RevId;

	*((PULONG)g_VMXCPU[uCPUID].pVMXONRegion) = uRevId;
	*((PULONG)g_VMXCPU[uCPUID].pVMCSRegion) = uRevId;

	Log("TIP:VMX�汾����Ϣ", uRevId);

	*((PULONG64)&uCr4) = GetCr4();
	uCr4.VMXE = 1;
	SetCr4(*((PULONG64)&uCr4));

	Vmx_VmxOn(g_VMXCPU[uCPUID].pVMXONRegion_PA.QuadPart);
	*((PULONG64)&uEflags) = GetRflags();
	if (uEflags.CF != 0)
	{
		Log("ERROR:VMXONָ�����ʧ��!", 0);
		return;
	}
	Log("SUCCESS:VMXONָ����óɹ�!", 0);
}
ULONG64 NTAPI VmxAdjustControls(
	ULONG64 Ctl,
	ULONG64 Msr
)
{
	LARGE_INTEGER MsrValue;

	MsrValue.QuadPart = ReadMsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}
EXTERN_C void NTAPI SetupVMCS(ULONG64 _rsp,ULONG64 _rip)
{
	_EFLAGS uEflags;
	ULONG64 GdtBase, IdtBase;
	SEGMENT_SELECTOR SegmentSelector;
	ULONG64 uCPUBase;
	ULONG64 uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();
	Vmx_VmClear(g_VMXCPU[uCPUID].pVMCSRegion_PA.QuadPart);
	*((PULONG64)&uEflags) = GetRflags();
	if (uEflags.CF != 0 || uEflags.ZF != 0)
	{
		Log("ERROR:VMCLEARָ�����ʧ��!", 0);
		return;
	}
	Log("SUCCESS:VMCLEARָ����óɹ�!", 0);
	Vmx_VmPtrld(g_VMXCPU[uCPUID].pVMCSRegion_PA.QuadPart);

	//
	// 1.Guest State Area
	//
	Vmx_VmWrite(GUEST_CR0, GetCr0());
	Vmx_VmWrite(GUEST_CR3, GetCr3());
	Vmx_VmWrite(GUEST_CR4, GetCr4());
	Vmx_VmWrite(GUEST_DR7, 0x400);
	Vmx_VmWrite(GUEST_RFLAGS, GetRflags());

	GdtBase = GetGdtBase();
	IdtBase = GetIdtBase();
	//
	// 1.Guest State Area
	//
	Vmx_VmWrite(GUEST_CR0, GetCr0());
	Vmx_VmWrite(GUEST_CR3, GetCr3());
	Vmx_VmWrite(GUEST_CR4, GetCr4());
	Vmx_VmWrite(GUEST_DR7, 0x400);
	Vmx_VmWrite(GUEST_RFLAGS, GetRflags());

	FillGuestSelectorData(GdtBase, ES, (USHORT)GetEs());
	FillGuestSelectorData(GdtBase, FS, (USHORT)GetFs());
	FillGuestSelectorData(GdtBase, DS, (USHORT)GetDs());
	FillGuestSelectorData(GdtBase, CS, (USHORT)GetCs());
	FillGuestSelectorData(GdtBase, SS, (USHORT)GetSs());
	FillGuestSelectorData(GdtBase, GS, (USHORT)GetGs());
	FillGuestSelectorData(GdtBase, TR, (USHORT)GetTr());
	FillGuestSelectorData(GdtBase, LDTR, (USHORT)GetLdtr());
	Vmx_VmWrite(GUEST_CS_BASE, 0);
	Vmx_VmWrite(GUEST_DS_BASE, 0);
	Vmx_VmWrite(GUEST_ES_BASE, 0);
	Vmx_VmWrite(GUEST_SS_BASE, 0);
	Vmx_VmWrite(GUEST_FS_BASE, ReadMsr(MSR_FS_BASE));
	Vmx_VmWrite(GUEST_GS_BASE, ReadMsr(MSR_GS_BASE));
	Vmx_VmWrite(GUEST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	Vmx_VmWrite(GUEST_IDTR_BASE, IdtBase);
	Vmx_VmWrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	Vmx_VmWrite(GUEST_IA32_DEBUGCTL, ReadMsr(MSR_IA32_DEBUGCTL));
	Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH, ReadMsr(MSR_IA32_DEBUGCTL) >> 32);
	Vmx_VmWrite(GUEST_IA32_EFER, ReadMsr(MSR_EFER));

	Vmx_VmWrite(GUEST_SYSENTER_CS, ReadMsr(MSR_IA32_SYSENTER_CS));
	Vmx_VmWrite(GUEST_SYSENTER_ESP, ReadMsr(MSR_IA32_SYSENTER_ESP));
	Vmx_VmWrite(GUEST_SYSENTER_EIP, ReadMsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry

	Vmx_VmWrite(GUEST_RSP,_rsp);
	Vmx_VmWrite(GUEST_RIP,_rip);

	Vmx_VmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	Vmx_VmWrite(GUEST_ACTIVITY_STATE, 0);
	Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);
	Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//
	// 2.Host State Area
	//
	Vmx_VmWrite(HOST_CR0, GetCr0());
	Vmx_VmWrite(HOST_CR3, GetCr3());
	Vmx_VmWrite(HOST_CR4, GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	Vmx_VmWrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	Vmx_VmWrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	Vmx_VmWrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	Vmx_VmWrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	Vmx_VmWrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	Vmx_VmWrite(HOST_TR_SELECTOR, GetTr() & 0xF8);


	Vmx_VmWrite(HOST_ES_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_CS_SELECTOR, KGDT64_R0_CODE);
	Vmx_VmWrite(HOST_SS_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_DS_SELECTOR, KGDT64_R0_DATA);
	Vmx_VmWrite(HOST_FS_SELECTOR, GetFs() & 0xf8);
	Vmx_VmWrite(HOST_GS_SELECTOR, GetGs() & 0xf8);
	Vmx_VmWrite(HOST_TR_SELECTOR, GetTr() & 0xf8);

	Vmx_VmWrite(HOST_FS_BASE, ReadMsr(MSR_FS_BASE));
	Vmx_VmWrite(HOST_GS_BASE, ReadMsr(MSR_GS_BASE));
	InitializeSegmentSelector(&SegmentSelector, (USHORT)GetTr(), GdtBase);
	Vmx_VmWrite(HOST_TR_BASE, SegmentSelector.base);

	Vmx_VmWrite(HOST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE, IdtBase);

	Vmx_VmWrite(HOST_IA32_EFER, ReadMsr(MSR_EFER));
	Vmx_VmWrite(HOST_IA32_SYSENTER_CS, ReadMsr(MSR_IA32_SYSENTER_CS));
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP, ReadMsr(MSR_IA32_SYSENTER_ESP));
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP, ReadMsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP, ((ULONG64)g_VMXCPU[uCPUID].pHostEsp) + 0x1FFF);//8KB 0x2000
	Vmx_VmWrite(HOST_RIP, (ULONG64)&VMMEntryPoint_fuc);//���ﶨ�����ǵ�VMM����������

													   //
													   // 3.��������п�����
													   //
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));

	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	Vmx_VmWrite(TSC_OFFSET, 0);
	Vmx_VmWrite(TSC_OFFSET_HIGH, 0);

	uCPUBase = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);

	//uCPUBase |= CPU_BASED_MOV_DR_EXITING; // ���ص��ԼĴ�������
	//uCPUBase |= CPU_BASED_USE_IO_BITMAPS; // ���ؼ��������Ϣ
	uCPUBase |= CPU_BASED_ACTIVATE_MSR_BITMAP; // ����MSR����

	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);

	/*
	Vmx_VmWrite(IO_BITMAP_A,0);
	Vmx_VmWrite(IO_BITMAP_A_HIGH,0);
	Vmx_VmWrite(IO_BITMAP_B,0);
	Vmx_VmWrite(IO_BITMAP_B_HIGH,0);
	*/

	Vmx_VmWrite(CR3_TARGET_COUNT, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE0, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE1, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE2, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE3, 0);

	//
	// 4.VMEntry���п�����
	//
	Vmx_VmWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER, MSR_IA32_VMX_ENTRY_CTLS));
	Vmx_VmWrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_ENTRY_INTR_INFO_FIELD, 0);


	//
	// 5.VMExit���п�����
	//
	Vmx_VmWrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	Vmx_VmWrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_EXIT_MSR_STORE_COUNT, 0);
	Vmx_VmLaunch();
	g_VMXCPU[uCPUID].bVTStartSuccess = FALSE;
}




NTSTATUS StartVT()
{
//	NTSTATUS status = STATUS_SUCCESS;



	KIRQL OldIrql;

	KeInitializeMutex(&g_GlobalMutex, 0);
	KeWaitForMutexObject(&g_GlobalMutex, Executive, KernelMode, FALSE, 0);
	ULONG64 uCPUID;
	for (int i = 0; i < KeNumberProcessors; i++)
	{
		KeSetSystemAffinityThreadEx((1i64 << i));

		OldIrql = KeRaiseIrqlToDpcLevel();
		//////////////////////
		if (!IsVTEnabled())goto bugcore;
	uCPUID = KeGetCurrentProcessorNumber();
	
		AllocateVMXRegion();
		SetupVMXRegion();

		g_VMXCPU[uCPUID].bVTStartSuccess = TRUE;

		SetupVMCS_fuc();
		
		if (g_VMXCPU[uCPUID].bVTStartSuccess)

			Log("VmLaunchָ����óɹ�!");
		else
			Log("ERROR:VmLaunchָ�����ʧ��!", Vmx_VmRead(VM_INSTRUCTION_ERROR));
		///////////////////////
	   bugcore:  KeLowerIrql(OldIrql);

		KeRevertToUserAffinityThread();
	}
	KeReleaseMutex(&g_GlobalMutex, FALSE);



	KdPrint(("startvt"));
	return NTSTATUS(1);
}

NTSTATUS StopVT()
{
	KdPrint(("stopvt"));
	return NTSTATUS(1);
}
