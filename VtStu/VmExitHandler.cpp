#include "MyVT.h"
#include "Hook.h"

#pragma warning(push)
#pragma warning(disable:4244)

//��ЩVmExit�¼�����������ɺ󣬻ص�Guestʱ��Ҫ��������VmExit�Ĵ���
//����VmCall��ʱ�򣬲������Ļ����ص�Guest�ּ�������VmCall
//����Guest��ǰִ�еĴ���
void VmmAdjustGuestRip()
{
	ULONG instLen = 0;
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);
	//��ȡGuest��ǰִ��ָ��ĳ���
	__vmx_vmread(VmExitInstructionLength, (SIZE_T*)&instLen);
	__vmx_vmwrite(GuestRip, (SIZE_T)(rip + instLen));
}


//�˳�VT����������CV��������Ŀ��
void VmxPrepareOff(GpRegisters* pGuestRegisters)
{
	/*
	������VM�˳�ʱ����������IDT��GDT��Limit����Ϊffff��
	��������Ļ���ȷ��ֵ
	*/
	ULONG_PTR gdt_limit = 0;
	__vmx_vmread(GuestGDTRLimit, &gdt_limit);

	ULONG_PTR gdt_base = 0;
	__vmx_vmread(GuestGDTRBase, &gdt_base);
	ULONG_PTR idt_limit = 0;
	__vmx_vmread(GuestIDTRLimit, &idt_limit);
	ULONG_PTR idt_base = 0;
	__vmx_vmread(GuestIDTRBase, &idt_base);

	Gdtr gdtr = { (USHORT)gdt_limit, gdt_base };
	Idtr idtr = { (USHORT)(idt_limit), idt_base };
	AsmWriteGDT(&gdtr);
	__lidt(&idtr);


	//����VmCallָ��
	ULONG_PTR exit_instruction_length = 0;
	__vmx_vmread(VmExitInstructionLength, &exit_instruction_length);
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);
	ULONG_PTR return_address = rip + exit_instruction_length;

	// Since the flag register is overwritten after VMXOFF, we should manually
	// indicates that VMCALL was successful by clearing those flags.
	// See: CONVENTIONS
	FlagRegister rflags = { 0 };
	__vmx_vmread(GuestRflags, (SIZE_T*)&rflags);

	rflags.fields.cf = FALSE;
	rflags.fields.pf = FALSE;
	rflags.fields.af = FALSE;
	rflags.fields.zf = FALSE;
	rflags.fields.sf = FALSE;
	rflags.fields.of = FALSE;
	rflags.fields.cf = FALSE;
	rflags.fields.zf = FALSE;

	// Set registers used after VMXOFF to recover the context. Volatile
	// registers must be used because those changes are reflected to the
	// guest's context after VMXOFF.
	pGuestRegisters->cx = return_address;
	__vmx_vmread(GuestRsp, &pGuestRegisters->dx);
	pGuestRegisters->ax = rflags.all;
}


//����MSR�Ķ�д��������CV����
VOID ReadWriteMsrHandle(GpRegisters* pGuestRegisters, BOOLEAN isRead)
{
	MSR msr = (MSR)__readmsr(pGuestRegisters->cx);

	BOOLEAN transfer_to_vmcs = false;
	VmcsField vmcs_field = {};
	switch (msr) {
	case MSR::MsrSysenterCs:
		vmcs_field = VmcsField::GuestIa32SYSENTERCS;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrSysenterEsp:
		vmcs_field = VmcsField::GuestIa32SYSENTERESP;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrSysenterEip:
		vmcs_field = VmcsField::GuestIa32SYSENTEREIP;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrDebugctl:
		vmcs_field = VmcsField::GuestIa32DebugCtl;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrGsBase:
		vmcs_field = VmcsField::GuestGsBase;
		transfer_to_vmcs = true;
		break;
	case MSR::MsrFsBase:
		vmcs_field = VmcsField::GuestFsBase;
		transfer_to_vmcs = true;
		break;
	default:
		break;
	}

	LARGE_INTEGER msr_value = {};
	if (isRead) {
		if (transfer_to_vmcs) {
			__vmx_vmread(vmcs_field, (SIZE_T*)&msr_value.QuadPart);
		}
		else {
			__vmx_vmread(msr, (SIZE_T*)&msr_value.QuadPart);
		}

		pGuestRegisters->ax = msr_value.LowPart;
		pGuestRegisters->dx = msr_value.HighPart;
	}
	else
	{
		msr_value.LowPart = (ULONG)pGuestRegisters->ax;
		msr_value.HighPart = (ULONG)pGuestRegisters->dx;
		if (transfer_to_vmcs) {
			__vmx_vmwrite(vmcs_field, (ULONG_PTR)msr_value.QuadPart);
		}
		else {
			__vmx_vmwrite(msr, (ULONG_PTR)msr_value.QuadPart);
		}
	}
}


BOOLEAN VmCallHandle(GpRegisters* pGuestRegisters)
{
	//x64�¶���fastcall����Լ��
	//VmCall�Ĺ��ܺ�
	ULONG_PTR num = pGuestRegisters->cx;
	//���ӵĲ���
	ULONG_PTR param = pGuestRegisters->dx;

	BOOLEAN ContinueVmx = TRUE;

	EptCommonEntry* pte = 0;
	PEptHookInfo hookInfo = 0;

	switch (num)
	{
	case CallExitVT:
		ContinueVmx = FALSE;
		VmxPrepareOff(pGuestRegisters);
		break;
	case CallEptHook:
		//HOOK��ʱ�򣬰�ԭ��������ҳ�ĳɸ��Ƴ�����ҳ�棬����ֻ��ִ��
		hookInfo = (PEptHookInfo)param;
		pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
		if (pte) {
			pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
			pte->fields.execute_access = 1;
			pte->fields.read_access = 0;
			pte->fields.write_access = 0;
		}
		break;
	case CallEptUnHook:
		//HOOK��ʱ�򣬰�ԭ��������ҳ�Ļ�ȥ�����Ҹ���ȫ��Ȩ��
		hookInfo = (PEptHookInfo)param;
		pte = GetPteByPhyAddr(hookInfo->RealPagePhyAddr);
		if (pte) {
			pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
			pte->fields.execute_access = 1;
			pte->fields.read_access = 1;
			pte->fields.write_access = 1;
		}
		break;
	default:
		Log("δ֪��VmCall");
		break;
	}

	return ContinueVmx;
}



VOID EptViolationHandle()
{
	//��ȡ����EptViolation�ĵ�ַ
	ULONG_PTR ExitPhyAddr = 0;
	__vmx_vmread(VmExitGuestPhysicalAddress, &ExitPhyAddr);

	//ͨ������EptViolation�ĵ�ַ�������ǲ��Ǹ�����HOOK�й�
	PEptHookInfo hookInfo = GetHookInfoByPA(ExitPhyAddr);

	if (hookInfo)
	{
		EptCommonEntry* pte = GetPteByPhyAddr(ExitPhyAddr);

		//�������EptViolationʱ����ǰҳ����ִ�У�������ֻ�����������Ҫô��ִ�в��ܶ�д��Ҫô�ܶ�д����ִ��
		//��ִ��˵�����Ƕ���дֻ��ִ�е�ҳ���������EptViolation��������дԭ����ҳ
		if (pte->fields.execute_access) {
			pte->fields.execute_access = 0;
			pte->fields.read_access = 1;
			pte->fields.write_access = 1;
			pte->fields.physial_address = hookInfo->RealPagePhyAddr >> 12;
		}
		else {
			//�������EptViolationʱ����ǰҳ�ǿɶ���д��˵������ִ�д�����EptViolation������ִ��HOOK����ҳ
			pte->fields.execute_access = 1;
			pte->fields.read_access = 0;
			pte->fields.write_access = 0;
			pte->fields.physial_address = hookInfo->FakePagePhyAddr >> 12;
		}
	}
	else {
		DbgBreakPoint();
	}
}





EXTERN_C BOOLEAN VmexitHandler(GpRegisters* pGuestRegisters)
{
	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	ULONG CurrentProcessorIndex = KeGetCurrentProcessorNumberEx(NULL);
	VmExitInformation ExitReason = { 0 };
	FlagRegister guestRflag = { 0 };
	BOOLEAN ContinueVmx = TRUE;
	ULONG_PTR Rip = 0;

	__vmx_vmread(GuestRip, &Rip);
	__vmx_vmread(VmExitReason, (SIZE_T*)(&ExitReason));


	switch (ExitReason.fields.reason)
	{
	case ExitTripleFault:
		Log("TripleFault %p", Rip);
		//VmmAdjustGuestRip();
		DbgBreakPoint();
		break;
	case ExitEptMisconfig:
		Log("ExitEptMisconfig");
		DbgBreakPoint();
		break;
	case ExitEptViolation:
		EptViolationHandle();
		break;
	case ExitCrAccess:
		Log("CrAccess %p", Rip);
		break;
		//msr��д���봦��
	case ExitMsrRead:
	{
		// Log("ExitMsrRead %p", Rip);
		ReadWriteMsrHandle(pGuestRegisters, TRUE);
		VmmAdjustGuestRip();
		break;
	}
	case ExitMsrWrite:
	{
		Log("ExitMsrWrite");
		ReadWriteMsrHandle(pGuestRegisters, FALSE);
		VmmAdjustGuestRip();
		break;
	}
	case ExitCpuid:
	{
		//Log("ExitCpuid");
		//���ʺ�Ƶ��
		int leaf = (int)pGuestRegisters->ax;
		int sub_leaf = (int)pGuestRegisters->cx;
		int result[4] = { 0 };
		__cpuidex((int*)&result, leaf, sub_leaf);

		//if (leaf ==1)
		//{
		//	//((CpuFeaturesEcx*)&result[2])->fields.
		//}
		pGuestRegisters->ax = result[0];
		pGuestRegisters->bx = result[1];
		pGuestRegisters->cx = result[2];
		pGuestRegisters->dx = result[3];
		VmmAdjustGuestRip();
		break;
	}
	case ExitIoInstruction:
	{
		Log("ExitIoInstruction");
		VmmAdjustGuestRip();
		break;
	}
	case ExitVmcall:
	{
		ContinueVmx = VmCallHandle(pGuestRegisters);
		//��������˳�VT������VmCallָ�����ִ��
		if (ContinueVmx) VmmAdjustGuestRip();
		break;
	}
	case ExitExceptionOrNmi:
	{
		Log("ExitExceptionOrNmi");
		VmExitInterruptionInformationField exception = { 0 };
		__vmx_vmread(VmExitInterruptionInformation, (SIZE_T*)&exception);

		if (exception.fields.interruption_type == kHardwareException)
		{
			//VmmpInjectInterruption(exception.fields.interruption_type,)
			exception.fields.valid = TRUE;
			__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
		}
		else if (exception.fields.interruption_type == kSoftwareException)
		{
			__vmx_vmwrite(VmEntryInterruptionInformation, exception.all);
			int exit_inst_length = 0;
			__vmx_vmread(VmExitInstructionLength, (SIZE_T*)&exit_inst_length);
			__vmx_vmwrite(VmEntryInstructionLength, exit_inst_length);
		}
		break;
	}
	case ExitMonitorTrapFlag:
	{
		Log("ExitMonitorTrapFlag");

		break;
	}
	case ExitHlt:
	{
		Log("ExitHlt");
		break;
	}
	case ExitVmclear:
	case ExitVmptrld:
	case ExitVmptrst:
	case ExitVmread:
	case ExitVmwrite:
	case ExitVmresume:
	case ExitVmoff:
	case ExitVmon:
	case ExitVmlaunch:
	case ExitVmfunc:
	case ExitInvept:
	case ExitInvvpid:
	{
		Log("vm inst");
		__vmx_vmread(GuestRflags, (SIZE_T*)&guestRflag);
		guestRflag.fields.cf = 1;
		__vmx_vmwrite(GuestRflags, guestRflag.all);
		VmmAdjustGuestRip();
		break;
	}		
	case ExitInvd:
	{
		Log("ExitInvd");
		AsmInvd();
		VmmAdjustGuestRip();
		break;
	}
	case ExitInvlpg:
	{
		Log("ExitInvlpg");
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, (SIZE_T*)&eq);
		InvVpidDescriptor desc = { 0 };
		desc.vpid = CurrentProcessorIndex + 1;
		desc.linear_address = eq.all;
		AsmInvvpid(kIndividualAddressInvalidation, (SIZE_T*)&desc);
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtsc:
	{
		Log("ExitRdtsc");

		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtsc();
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtscp:
	{
		Log("ExitRdtscp");

		unsigned int tsc_aux = 0;
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtscp(&tsc_aux);
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		pGuestRegisters->cx = tsc_aux;
		VmmAdjustGuestRip();
		break;
	}
	case ExitXsetbv:
	{
		Log("ExitXsetbv");

		ULARGE_INTEGER value = { 0 };
		value.LowPart = pGuestRegisters->ax;
		value.HighPart = pGuestRegisters->dx;
		_xsetbv(pGuestRegisters->cx, value.QuadPart);

		VmmAdjustGuestRip();
		break;
	}
	default:
		Log("Unexpected Exit %d", ExitReason.fields.reason);
		DbgBreakPoint();
		break;
	}

	if (irql < DISPATCH_LEVEL) {
		KeLowerIrql(irql);
	}

	return ContinueVmx;
}

#pragma warning(pop)
