// 主要用来编写驱动的加载及退出的代码

#include "MyVT.h"
#include<Ndis.h>

MyVT* AllCPU[128] = { 0 };  // CPU数组,因为每一个CPU上都需要VMM、VMX、VMCS等


EXTERN_C VOID LoadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//获取当前CPU核心的号数
	ULONG index = KeGetCurrentProcessorIndex();
	if (CheckVTSupport() && CheckVTEnable())
	{
		Log("[CPU:%d]支持虚拟化", index);
		MyVT* myVt= new MyVT(index);
		if (myVt->StartVT())
		{
			AllCPU[index] = myVt; 
			Log("[CPU:%d]启动VT成功", index);
		}
		else {
			Log("[CPU:%d]启动VT失败", index);
		}
	}
	else {
		Log("[CPU:%d]不支持虚拟化", index);
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
	KeGenericCallDpc(UnloadVT, NULL);
	//延时等一下VT退出完毕
	NdisStallExecution(50);
	if (EptMem) {
		kfree(EptMem);
		EptMem = 0;
	}
	Log("Ept Free Successfully!");
	Log("驱动卸载");
}

//已C语言方式导出，C++为支持函数重载，函数名会被改变，导致编译不通过
EXTERN_C VOID DriverEntry(PDRIVER_OBJECT driver, UNICODE_STRING path)
{
	//用不到的参数用UNREFERENCED_PARAMETER括起来，否则报错，也在属性->C/C++ ->“警告视为错误”关掉，这里及之后的文章里都不关
	UNREFERENCED_PARAMETER(path);
	Log("驱动加载");
	driver->DriverUnload = DriverUnload;
	UseEpt = TRUE;
	if (!InitEpt()) {
		UseEpt = FALSE;
		Log("Ept Initialized Failed!");
	}
	Log("Ept Initialized Successfully!");
	KeGenericCallDpc(LoadVT, NULL);
}