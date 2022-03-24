#include "MyVT.h"

MyVT::MyVT(int cupIndex) {
	this->cupIndex = cupIndex;
	this->VMX_Region= (ULONG_PTR)kmalloc(PAGE_SIZE);
	this->VMCS_Region = (ULONG_PTR)kmalloc(PAGE_SIZE);
	this->MsrBitmap = (ULONG_PTR)kmalloc(PAGE_SIZE);
	VmmStack = (PCHAR)kmalloc(VMM_STACK_SIZE);
	Log("当前CPUIndex:%d", cupIndex);
}
MyVT::~MyVT()
{
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	if (cr4.fields.vmxe)
	{
		cr4.fields.vmxe = FALSE;
		__writecr4(cr4.all);
	}
	kfree((PVOID)VMX_Region);
	kfree((PVOID)VMCS_Region);
	kfree((PVOID)MsrBitmap);
	kfree(VmmStack);

	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (msr.fields.lock)
	{
		msr.fields.lock = FALSE;
		msr.fields.enable_vmxon = FALSE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}
}


BOOLEAN MyVT::ExecuteVMXON()
{
	//填充版本号，读取msr480H可以获取当前VT版本
#pragma warning(push)
#pragma warning(disable:4244)
	* (ULONG*)VMX_Region = __readmsr(MsrVmxBasic);  // 填写VMX中版本号
	*(ULONG*)VMCS_Region = __readmsr(MsrVmxBasic);  // 填写VMCS中版本号
#pragma warning(pop)
	//设置CR4,设置CR4.VMXE标志开启了VT
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	cr4.fields.vmxe = TRUE;
	__writecr4(cr4.all);

	//对每个CPU开启VMXON指令的限制
	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (!msr.fields.lock)
	{
		// 对相关标志位进行设置,这样其他VT驱动检测的时候该CPU就过不了检测
		msr.fields.lock = TRUE;
		msr.fields.enable_vmxon = TRUE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}

	//执行VMXON
	ULONG_PTR phyaddr = MmGetPhysicalAddress((PVOID)VMX_Region).QuadPart;
	__vmx_on(&phyaddr); // 执行完VMXON后就进入了VMM

	FlagRegister eflags = { 0 };
	*(ULONG_PTR*)(&eflags) = __readeflags();
	// 根据手册说明如果VMXON执行成功则eflags中的CF位不为0
	if (eflags.fields.cf != 0) {
		Log("[CPU:%d]VMXON执行失败！", cupIndex);
		return FALSE;
	}

	phyaddr = MmGetPhysicalAddress((PVOID)VMCS_Region).QuadPart;
	
	//初始化VMCS区域
	__vmx_vmclear(&phyaddr);
	
	//选中当前VMCS区域，为填充VMCS区域作准备
	__vmx_vmptrld(&phyaddr);
	return TRUE;
}



BOOLEAN MyVT::StartVT()
{
	isEnable = ExecuteVMXON();
	if (!isEnable) {
		Log("[CPU;%d]VMXON失败！",MyVT::cupIndex);
		return FALSE;
	}

	//利用联合体可共享内存的方式，可以获取的对象的成员函数的地址
	FunAddr funAddr = { 0 };
	funAddr.fun=&MyVT::InitVMCS;

	isEnable = AsmVmxLaunch(funAddr.addr, this);

	return isEnable;
}
