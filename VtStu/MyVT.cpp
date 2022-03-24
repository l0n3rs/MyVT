#include "MyVT.h"

MyVT::MyVT(int cupIndex) {
	this->cupIndex = cupIndex;
	this->VMX_Region= (ULONG_PTR)kmalloc(PAGE_SIZE);
	this->VMCS_Region = (ULONG_PTR)kmalloc(PAGE_SIZE);
	this->MsrBitmap = (ULONG_PTR)kmalloc(PAGE_SIZE);
	VmmStack = (PCHAR)kmalloc(VMM_STACK_SIZE);
	Log("��ǰCPUIndex:%d", cupIndex);
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
	//���汾�ţ���ȡmsr480H���Ի�ȡ��ǰVT�汾
#pragma warning(push)
#pragma warning(disable:4244)
	* (ULONG*)VMX_Region = __readmsr(MsrVmxBasic);  // ��дVMX�а汾��
	*(ULONG*)VMCS_Region = __readmsr(MsrVmxBasic);  // ��дVMCS�а汾��
#pragma warning(pop)
	//����CR4,����CR4.VMXE��־������VT
	Cr4 cr4 = { 0 };
	cr4.all = __readcr4();
	cr4.fields.vmxe = TRUE;
	__writecr4(cr4.all);

	//��ÿ��CPU����VMXONָ�������
	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (!msr.fields.lock)
	{
		// ����ر�־λ��������,��������VT��������ʱ���CPU�͹����˼��
		msr.fields.lock = TRUE;
		msr.fields.enable_vmxon = TRUE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}

	//ִ��VMXON
	ULONG_PTR phyaddr = MmGetPhysicalAddress((PVOID)VMX_Region).QuadPart;
	__vmx_on(&phyaddr); // ִ����VMXON��ͽ�����VMM

	FlagRegister eflags = { 0 };
	*(ULONG_PTR*)(&eflags) = __readeflags();
	// �����ֲ�˵�����VMXONִ�гɹ���eflags�е�CFλ��Ϊ0
	if (eflags.fields.cf != 0) {
		Log("[CPU:%d]VMXONִ��ʧ�ܣ�", cupIndex);
		return FALSE;
	}

	phyaddr = MmGetPhysicalAddress((PVOID)VMCS_Region).QuadPart;
	
	//��ʼ��VMCS����
	__vmx_vmclear(&phyaddr);
	
	//ѡ�е�ǰVMCS����Ϊ���VMCS������׼��
	__vmx_vmptrld(&phyaddr);
	return TRUE;
}



BOOLEAN MyVT::StartVT()
{
	isEnable = ExecuteVMXON();
	if (!isEnable) {
		Log("[CPU;%d]VMXONʧ�ܣ�",MyVT::cupIndex);
		return FALSE;
	}

	//����������ɹ����ڴ�ķ�ʽ�����Ի�ȡ�Ķ���ĳ�Ա�����ĵ�ַ
	FunAddr funAddr = { 0 };
	funAddr.fun=&MyVT::InitVMCS;

	isEnable = AsmVmxLaunch(funAddr.addr, this);

	return isEnable;
}
