// 主要用来编写一些工具函数

#include <intrin.h>
#include "def.h"



/*
23.6 DISCOVERING SUPPORT FOR VMX
Before system software enters into VMX operation, it must discover the presence of VMX support in the processor.
System software can determine whether a processor supports VMX operation using CPUID. If
CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported. See Chapter 3, “Instruction Set Reference, A-L” of
Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2A.
The VMX architecture is designed to be extensible so that future processors in VMX operation can support additional features not present in first-generation implementations of the VMX architecture. The availability of extensible VMX features is reported to software using a set of VMX capability MSRs (see Appendix A, “VMX Capability
Reporting Facility”).

*/
BOOLEAN CheckVTSupport() {
	int ctx[4] = { 0 };
	// 获取CPU信息，如果成功,ctx中分别会存放eax到edx的信息
	__cpuidex(ctx, 1,0);
	// //检查ecx的第五位是否为0,0表示该CPU不支持VT,IA32手册卷3C 23.6
	if ((ctx[2]>>5)&1==0)
	{
		//不支持虚拟化
		return FALSE;
	}
	return TRUE;
}

BOOLEAN CheckVTEnable() {
	ULONG_PTR msr;
	msr = __readmsr(0x3A);
	//检查第0位是否为0,也就是BIOS中VT是否开启,0是关闭(见IA32手册卷3C 23.7,因为Windows系统本身就是在保护模式下,所以不需要检查CR0了)
	//Bit 0是Lock位,Bit 2是Enable VMX in outside SMX operation
	if ((msr & 1) == 0&&(msr>>2&1== 0))
		return FALSE;

	return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t size) {
	if (size == 0) {
		size = 1;
	}
	return ExAllocatePool(NonPagedPool, size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, SIZE_T size) {
	UNREFERENCED_PARAMETER(size);
	if (p) {
		ExFreePool(p);
	}
}

PVOID kmalloc(ULONG_PTR size)
{
	PHYSICAL_ADDRESS MaxAddr = { 0 };
	MaxAddr.QuadPart = -1; // MaxAddr.QuadPart=0xffffffff; 上限
	//MmAllocateContiguousMemory分配的是非分页内存(不会被交换到硬盘上去),且保证在物理内存中是连续的
	PVOID addr = MmAllocateContiguousMemory(size, MaxAddr);
	// PVOID addr = ExAllocatePool(NonPagedPool,size);
	if (addr) RtlSecureZeroMemory(addr, size);
	return addr;
}

VOID kfree(PVOID p)
{
	if (p) MmFreeContiguousMemory(p);
}