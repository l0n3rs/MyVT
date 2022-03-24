// ��Ҫ������д�����ļ��ؼ��˳��Ĵ���

#include "MyVT.h"
#include<Ndis.h>
#include "Hook.h"

MyVT* AllCPU[128] = { 0 };  // CPU����,��Ϊÿһ��CPU�϶���ҪVMM��VMX��VMCS��


EXTERN_C VOID LoadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//��ȡ��ǰCPU���ĵĺ���
	ULONG index = KeGetCurrentProcessorIndex();
	if (CheckVTSupport() && CheckVTEnable())
	{
		Log("[CPU:%d]֧�����⻯", index);
		MyVT* myVt= new MyVT(index);
		if (myVt->StartVT())
		{
			AllCPU[index] = myVt; 
			Log("[CPU:%d]����VT�ɹ�", index);
		}
		else {
			Log("[CPU:%d]����VTʧ��", index);
		}
	}
	else {
		Log("[CPU:%d]��֧�����⻯", index);
	}
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

EXTERN_C VOID UnloadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	ULONG index = KeGetCurrentProcessorIndex();
	if (AllCPU[index] && AllCPU[index]->isEnable)  AsmVmxCall(CallExitVT, NULL);
	if (AllCPU[index]) delete AllCPU[index];
	Log("[CPU:%d] UnloadVT", index);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}



EXTERN_C VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
	//������HOOK����VT
	DestroyEptHook();
	//��һ���������
	NdisStallExecution(50);
	KeGenericCallDpc(UnloadVT, NULL);
	//��ʱ��һ��VT�˳����
	NdisStallExecution(50);
	if (EptMem) {
		kfree(EptMem);
		EptMem = 0;
	}
	Log("Ept Free Successfully!");
	Log("����ж��");
}

//��C���Է�ʽ������C++Ϊ֧�ֺ������أ��������ᱻ�ı䣬���±��벻ͨ��
EXTERN_C VOID DriverEntry(PDRIVER_OBJECT driver, UNICODE_STRING path)
{
	//�ò����Ĳ�����UNREFERENCED_PARAMETER�����������򱨴���Ҳ������->C/C++ ->��������Ϊ���󡱹ص������Ｐ֮��������ﶼ����
	UNREFERENCED_PARAMETER(path);
	Log("��������");
	driver->DriverUnload = DriverUnload;
	UseEpt = TRUE;
	if (!InitEpt()) {
		UseEpt = FALSE;
		Log("Ept Initialized Failed!");
	}
	Log("Ept Initialized Successfully!");
	KeGenericCallDpc(LoadVT, NULL);
	HookTest();
}