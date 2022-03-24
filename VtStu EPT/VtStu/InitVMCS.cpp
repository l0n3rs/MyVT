#include "MyVT.h"
#include <intrin.h>
#include "Asm.h"

//根据段选择子获取段描述符
SegmentDescriptor* VmpGetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector) {

	const SegmentSelector ss = { segment_selector };
	return (SegmentDescriptor*)(
		descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}


//根据段描述符获取段基址
ULONG_PTR VmpGetSegmentBaseByDescriptor(const SegmentDescriptor* segment_descriptor) {

	// Calculate a 32bit base address
	const ULONG_PTR base_high = { segment_descriptor->fields.base_high << (6 * 4) };
	const ULONG_PTR base_middle = { segment_descriptor->fields.base_mid << (4 * 4) };
	const ULONG_PTR base_low = { segment_descriptor->fields.base_low };

	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (!segment_descriptor->fields.system) {
		SegmentDesctiptorX64* desc64 = (SegmentDesctiptorX64*)(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}


//根据段选择子获取段基址
ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector) {

	SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		SegmentDescriptor* local_segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		ULONG_PTR  ldt_base =
			VmpGetSegmentBaseByDescriptor(local_segment_descriptor);


		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}


//根据段选择子获取段属性(Type域)
ULONG VmxGetSegmentAccessRight(USHORT segment_selector) {

	VmxRegmentDescriptorAccessRight access_right = { 0 };
	if (segment_selector) {
		const SegmentSelector ss = { segment_selector };
		ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = (ULONG)(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = FALSE;
	}
	else {
		access_right.fields.unusable = TRUE;
	}
	return access_right.all;
}


// 读MSR寄存器解析需要设置的位置
ULONG VmxAdjustControlValue(ULONG Msr, ULONG Ctl)
{
	LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = __readmsr(Msr);  // Msr读出来的是64Bit数据,所以需要LARGE_INTEGER来装,QuadPart相当于直接把LARGE_INTEGER当64Bit数据使用
	// x64下ULONG_PTR是64位的，x86下ULONG_PTR是32位的
	Ctl &= MsrValue.HighPart;     //前32位为0的位置表示那些必须设置位0
	Ctl |= MsrValue.LowPart;      //后32位为1的位置表示那些必须设置位1
	return Ctl;
}



// 初始化VMCS,填写VMCS
BOOLEAN MyVT::InitVMCS(PVOID guestStack, PVOID guestResumeRip)
{
	// VMCS的版本号等前几个字段在前面已经填写
	// 还差最重要的VMCS 数据区没有填写
	// VMCS DATA:Guest-state area、Host-state area、VM-execution control fields、VM-exit control fields、VM-entry control fields、VM-exit information fields


	// APPENDIX A VMX CAPABILITY REPORTING FACILITY
	// IA32_VMX_BASIC MSR (index 480H)
	Ia32VmxBasicMsr vBMsr = { 0 };
	vBMsr.all = __readmsr(MsrVmxBasic);



	// 配置VM-EXECUTION控制域,参考Intel 24.6 VM-EXECUTION CONTROL FIELDS
	// 1.配置基于pin的vm执行控制信息域(24.6.1 Pin-Based VM-Execution Controls)
	VmxPinBasedControls vm_pinctl_requested = { 0 };
	VmxPinBasedControls vm_pinctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTruePinbasedCtls : MsrVmxPinbasedCtls,
							  vm_pinctl_requested.all) };
	__vmx_vmwrite(PinBasedVmExecutionControls, vm_pinctl.all);

	// 2.配置基于处理器的主vm执行控制信息域(24.6.2 Processor-Based VM-Execution Controls Table 24-6)
	VmxProcessorBasedControls vm_procctl_requested = { 0 };
	//vm_procctl_requested.fields.cr3_load_exiting = TRUE;//拦截MOV to CR3
	//vm_procctl_requested.fields.cr3_store_exiting = TRUE;//拦截mov from cr3
	//vm_procctl_requested.fields.cr8_load_exiting = TRUE;//拦截mov to cr8
	//vm_procctl_requested.fields.cr8_store_exiting = TRUE;//拦截 mov from cr8
	//vm_procctl_requested.fields.mov_dr_exiting = TRUE; //拦截调试寄存器访问
	//vm_procctl_requested.fields.use_io_bitmaps = TRUE; //拦截io指令
	//vm_procctl_requested.fields.unconditional_io_exiting = TRUE;//无条件拦截io指令
	vm_procctl_requested.fields.use_msr_bitmaps = TRUE;  //拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit
	vm_procctl_requested.fields.activate_secondary_control = TRUE;
	VmxProcessorBasedControls vm_procctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueProcBasedCtls
											  : MsrVmxProcBasedCtls,
							  vm_procctl_requested.all) };
	__vmx_vmwrite(PrimaryProcessorBasedVmExecutionControls, vm_procctl.all);

	// 3.配置基于处理器的辅助vm执行控制信息域(24.6.2 Processor-Based VM-Execution Controls Table 24-7)
	VmxSecondaryProcessorBasedControls vm_procctl2_requested = { 0 };
	//vm_procctl2_requested.fields.descriptor_table_exiting = TRUE;//拦截LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR. 
	vm_procctl2_requested.fields.enable_rdtscp = TRUE;  // for Win10
	vm_procctl2_requested.fields.enable_invpcid = TRUE;        // for Win10
	vm_procctl2_requested.fields.enable_xsaves_xstors = TRUE;  // for Win10
	VmxSecondaryProcessorBasedControls vm_procctl2 = { VmxAdjustControlValue(
		MsrVmxProcBasedCtls2, vm_procctl2_requested.all) };
	__vmx_vmwrite(SecondaryProcessorBasedVmExecutionControls, vm_procctl2.all);




	// EPT部分1
	if (UseEpt) {
		vm_procctl2_requested.fields.enable_ept = TRUE;//开启ept
		vm_procctl2_requested.fields.enable_vpid = TRUE;
	}




	//配置VM-ENTRY控制域,Intel 24.8 VM-ENTRY CONTROL FIELDS
	VmxVmEntryControls vm_entryctl_requested = { 0 };
	//vm_entryctl_requested.fields.load_debug_controls = TRUE;
	vm_entryctl_requested.fields.ia32e_mode_guest = TRUE; //64系统必须填
	VmxVmEntryControls vm_entryctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueEntryCtls : MsrVmxEntryCtls,
		vm_entryctl_requested.all) };

	__vmx_vmwrite(VmEntryControls, vm_entryctl.all);





	//配置VM-EXIT控制域,Intel 24.7 VM-EXIT CONTROL FIELDS
	VmxVmExitControls vm_exitctl_requested = { 0 };
	vm_exitctl_requested.fields.host_address_space_size = TRUE;//64系统必须填
	VmxVmExitControls vm_exitctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueExitCtls : MsrVmxExitCtls,
		vm_exitctl_requested.all) };
	__vmx_vmwrite(VmExitControls, vm_exitctl.all);

	//配置其它控制域(Intel 24.6.6 Guest/Host Masks and Read Shadows for CR0 and CR4)
	Cr0 cr0_mask = { 0 };
	Cr0 cr0_shadow = { __readcr0() };

	Cr4 cr4_mask = { 0 };
	Cr4 cr4_shadow = { __readcr4() };
	//用于有条件拦截cr0,cr4的访问
	__vmx_vmwrite(Cr0GuestHostMask, cr0_mask.all);
	__vmx_vmwrite(Cr4GuestHostMask, cr4_mask.all);
	__vmx_vmwrite(Cr0ReadShadow, 0);// cr0_shadow.all);
	__vmx_vmwrite(Cr4ReadShadow, 0);// cr4_shadow.all);

	// 配置MSR-Bitmap Address,参考Intel 24.6.9 MSR-Bitmap Address
	ULONG_PTR MsrBitmapPhyAddr = MmGetPhysicalAddress((PVOID)MsrBitmap).QuadPart;
	__vmx_vmwrite(MsrBitmap, MsrBitmapPhyAddr);

	// 配置Exception Bitmap,24.6.3 Exception Bitmap
	ULONG_PTR exception_bitmap = 0;
	__vmx_vmwrite(ExceptionBitmap, exception_bitmap);





	// EPT部分2
	if (UseEpt) {
		ULONG processor = KeGetCurrentProcessorNumberEx(NULL);
		__vmx_vmwrite(EptPointer, EptP.all);
		__vmx_vmwrite(VirtualProcessorId, processor + 1);
	}




	//配置Guest State,主要是寄存器域(参考 Intel 24.4 GUEST-STATE AREA)
	Gdtr gdtr = { 0 };
	_sgdt(&gdtr);

	Idtr idtr = { 0 };
	__sidt(&idtr);

	__vmx_vmwrite(GuestEsSelector, AsmReadES());
	__vmx_vmwrite(GuestCsSelector, AsmReadCS());
	__vmx_vmwrite(GuestSsSelector, AsmReadSS());
	__vmx_vmwrite(GuestDsSelector, AsmReadDS());
	__vmx_vmwrite(GuestFsSelector, AsmReadFS());
	__vmx_vmwrite(GuestGsSelector, AsmReadGS());
	__vmx_vmwrite(GuestLDTRSelector, AsmReadLDTR());
	__vmx_vmwrite(GuestTRSelector, AsmReadTR());

	__vmx_vmwrite(GuestVmcsLinkPointer, MAXULONG64);
	__vmx_vmwrite(GuestIa32DebugCtl, __readmsr(MsrDebugctl));

	__vmx_vmwrite(GuestEsLimit, GetSegmentLimit(AsmReadES()));
	__vmx_vmwrite(GuestCsLimit, GetSegmentLimit(AsmReadCS()));
	__vmx_vmwrite(GuestSsLimit, GetSegmentLimit(AsmReadSS()));
	__vmx_vmwrite(GuestDsLimit, GetSegmentLimit(AsmReadDS()));
	__vmx_vmwrite(GuestFsLimit, GetSegmentLimit(AsmReadFS()));
	__vmx_vmwrite(GuestGsLimit, GetSegmentLimit(AsmReadGS()));
	__vmx_vmwrite(GuestLDTRLimit, GetSegmentLimit(AsmReadLDTR()));
	__vmx_vmwrite(GuestTRLimit, GetSegmentLimit(AsmReadTR()));
	__vmx_vmwrite(GuestGDTRLimit, gdtr.limit);
	__vmx_vmwrite(GuestIDTRLimit, idtr.limit);

	__vmx_vmwrite(GuestEsAccessRight, VmxGetSegmentAccessRight(AsmReadES()));
	__vmx_vmwrite(GuestCsAccessRight, VmxGetSegmentAccessRight(AsmReadCS()));
	__vmx_vmwrite(GuestSsAccessRight, VmxGetSegmentAccessRight(AsmReadSS()));
	__vmx_vmwrite(GuestDsAccessRight, VmxGetSegmentAccessRight(AsmReadDS()));
	__vmx_vmwrite(GuestFsAccessRight, VmxGetSegmentAccessRight(AsmReadFS()));
	__vmx_vmwrite(GuestGsAccessRight, VmxGetSegmentAccessRight(AsmReadGS()));
	__vmx_vmwrite(GuestLDTRAccessRight, VmxGetSegmentAccessRight(AsmReadLDTR()));
	__vmx_vmwrite(GuestTRAccessRight, VmxGetSegmentAccessRight(AsmReadTR()));
	__vmx_vmwrite(GuestIa32SYSENTERCS, __readmsr(MsrSysenterCs));

	__vmx_vmwrite(GuestCr0, __readcr0());
	__vmx_vmwrite(GuestCr3, __readcr3());
	__vmx_vmwrite(GuestCr4, __readcr4());

	__vmx_vmwrite(GuestEsBase, 0);
	__vmx_vmwrite(GuestCsBase, 0);
	__vmx_vmwrite(GuestSsBase, 0);
	__vmx_vmwrite(GuestDsBase, 0);
#pragma warning(push)
#pragma warning(disable:4245)
	__vmx_vmwrite(GuestFsBase, __readmsr(MsrFsBase));
	__vmx_vmwrite(GuestGsBase, __readmsr(MsrGsBase));

	__vmx_vmwrite(GuestLDTRBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
	__vmx_vmwrite(GuestTRBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	__vmx_vmwrite(GuestGDTRBase, gdtr.base);
	__vmx_vmwrite(GuestIDTRBase, idtr.base);
	__vmx_vmwrite(GuestDr7, __readdr(7));
	__vmx_vmwrite(GuestRsp, (SIZE_T)guestStack);
	__vmx_vmwrite(GuestRip, (SIZE_T)guestResumeRip);
	__vmx_vmwrite(GuestRflags, __readeflags());
	__vmx_vmwrite(GuestIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	__vmx_vmwrite(GuestIa32SYSENTEREIP, __readmsr(MsrSysenterEip));






	// 配置Host State,参考 Intel 24.5 HOST-STATE AREA
	// 之所以 0xf8 是因为Chapter 26中VM Entries存在检查,Vmlaunch并没有要求,是为下次VMEXIT后VMEntry设置的.
	// 参考26.2.3 Checks on Host Segment and Descriptor-Table Registers
	__vmx_vmwrite(HostEsSelector, AsmReadES() & 0xf8);
	__vmx_vmwrite(HostCsSelector, AsmReadCS() & 0xf8);
	__vmx_vmwrite(HostSsSelector, AsmReadSS() & 0xf8);
	__vmx_vmwrite(HostDsSelector, AsmReadDS() & 0xf8);
	__vmx_vmwrite(HostFsSelector, AsmReadFS() & 0xf8);
	__vmx_vmwrite(HostGsSelector, AsmReadGS() & 0xf8);
	__vmx_vmwrite(HostTrSelector, AsmReadTR() & 0xf8);
	__vmx_vmwrite(HostIa32SYSENTERCS, __readmsr(MsrSysenterCs));
	__vmx_vmwrite(HostCr0, __readcr0());
	__vmx_vmwrite(HostCr3, __readcr3());
	__vmx_vmwrite(HostCr4, __readcr4());
	__vmx_vmwrite(HostFsBase, __readmsr(MsrFsBase));
	__vmx_vmwrite(HostGsBase, __readmsr(MsrGsBase));
#pragma warning(pop)
	__vmx_vmwrite(HostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	__vmx_vmwrite(HostGDTRBase, gdtr.base);
	__vmx_vmwrite(HostIDTRBase, idtr.base);
	__vmx_vmwrite(HostIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	__vmx_vmwrite(HostIa32SYSENTEREIP, __readmsr(MsrSysenterEip));




	// VMLAUNCH
	//执行vmlaunch进入Host的时候的Host运行的栈
	__vmx_vmwrite(HostRsp, (SIZE_T)(VmmStack + VMM_STACK_SIZE - 0x1000));
	//执行vmlaunch进入Host，VmExit的时候host从AsmVmmEntryPoint这个函数开始运行
	__vmx_vmwrite(HostRip, (SIZE_T)AsmVmmEntryPoint);
	__vmx_vmlaunch();  // 执行成功就从Host进入到了Guest




	// VMLAUNCH Error
	//如果执行到这里,说明失败了
	ULONG_PTR errorCode = 0;
	__vmx_vmread(VmVMInstructionError, &errorCode);
	Log("VmLaunch Failed,ErrorCode: %d", errorCode);

	return FALSE;
}

