#pragma once
#include "def.h"
#include"Asm.h"


EXTERN_C Eptp EptP;
EXTERN_C PCHAR EptMem;
EXTERN_C BOOLEAN UseEpt;
EXTERN_C BOOLEAN InitEpt();
EXTERN_C EptCommonEntry* GetPteByPhyAddr(ULONG_PTR addr);


class MyVT
{
public:
	int cupIndex;   // CPU下标
	BOOLEAN isEnable;   // 当前的CPU是否已经成功启动VT
	BOOLEAN StartVT();       // 启动VT
	MyVT(int cupIndex);
	~MyVT();
private:
	// VMX 区域主要用于保存host的一些运行信息,至于如何使用这块内存我们不需要关心,只需要分配一页内存出来给CPU即可
	ULONG_PTR VMX_Region;   // VMX内存区域

	// Virtual-Machine Control Structure,翻译过来就是虚拟机控制结构,用于填写各种配置各种虚拟机控制信息,比如拦截读写MSR,读写CR3等等
	ULONG_PTR VMCS_Region;  // VMCS内存区域

	// 如果要拦截Msr读写,需要配置这个
	ULONG_PTR MsrBitmap;    // MSRBitMap内存区域

	// Host运行时的栈空间
	PCHAR VmmStack;         // VMMStack内存区域,Host使用

	BOOLEAN ExecuteVMXON();  // 执行VMXON

	BOOLEAN InitVMCS(PVOID guestStack, PVOID guestResumeRip);
};


//用于获取C++对象成员函数地址
typedef union
{
	PVOID addr;
	BOOLEAN(MyVT::* fun)(PVOID, PVOID);
} FunAddr;