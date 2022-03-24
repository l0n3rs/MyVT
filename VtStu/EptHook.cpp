#include "HOOK.h"
#include "nmd_assembly.h"

EptHookInfo HidePageEntry = { 0 };
PSYSTEM_SERVICE_TABLE SsdtAddr = 0;

UINT64 GetSSDT()
{
	// IA32_LSTAR（0xC0000082）：长模式（Long Mode，即64位）下，SYSCALL的内核RIP相对寻址。
	PUCHAR msr = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR startaddr = 0, Endaddr = 0;
	PUCHAR i = NULL;
	UCHAR b1, b2, b3;
	ULONG temp = 0;
	ULONGLONG addr = 0;

	if (*(msr + 0x9) == 0x00)
	{
		startaddr = msr;
		Endaddr = startaddr + 0x500;
	}
	else if (*(msr + 0x9) == 0x70)
	{
		PUCHAR pKiSystemCall64Shadow = msr;
		PUCHAR EndSearchAddress = pKiSystemCall64Shadow + 0x500;
		INT Temp = 0;
		for (i = pKiSystemCall64Shadow; i < EndSearchAddress; i++)
		{
			// //使用MmIsAddressValid()函数检查地址是否有页面错误，但是微软并不建议使用此函数
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				if (*i == 0xe9 && *(i + 5) == 0xc3)
				{
					memcpy(&Temp, i + 1, 4);
					startaddr = Temp + (i + 5);
					Endaddr = startaddr + 0x500;
				}
			}
		}
	}

	for (i = startaddr; i < Endaddr; i++)
	{
		b1 = *i;
		b2 = *(i + 1);
		b3 = *(i + 2);
		//对比特征值
		//fffff804`2f678184 4c8d15f5663900  lea     r10,[nt!KeServiceDescriptorTable (fffff804`2fa0e880)]
		//fffff804`2f67818b 4c8d1deee73700  lea     r11, [nt!KeServiceDescriptorTableShadow(fffff804`2f9f6980)]
		if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
		{
			memcpy(&temp, i + 3, 4);
			addr = (ULONGLONG)temp + (ULONGLONG)i + 7;
			return addr;
		}
	}
	return 0;
}

UINT64 GetSsdtFunAddr(ULONG dwIndex)
{
	if (!SsdtAddr) {
		SsdtAddr = (PSYSTEM_SERVICE_TABLE)GetSSDT();
		if (!SsdtAddr) return 0;
	}

	PULONG lpBase = (PULONG)SsdtAddr->ServiceTableBase;  // 系统服务函数表
	ULONG dwCount = (ULONG)SsdtAddr->NumberOfServices;   // 服务号总数
	UINT64 lpAddr = 0;
	ULONG dwOffset = lpBase[dwIndex];					 // X64中ServiceTableBase存放的是SSDT函数相对于ServiceTableBase的偏移 * 0x10的值

	if (dwIndex >= dwCount) return NULL;				 // 服务号校验

	if (dwOffset & 0x80000000)							 // 0x80000000=1和63个0
		// 算数右移,如果最高位为1，则右移后最高位需要补1，补1后最高位再次是1，再次右移后最高位依然需要补1。
		// 由于是右移四位，故需要补四次二进制的1，0x1111即为0XF，故最高位补F
		dwOffset = (dwOffset >> 4) | 0xF0000000;  // >>4是除去0x10取出真正的偏移
	else
		dwOffset >>= 4; // >>4是除去0x10取出真正的偏移
	lpAddr = (UINT64)((PUCHAR)lpBase + (LONG)dwOffset);  // 偏移+基址即可得到该函数的地址
	return lpAddr;
}

//获取>=12个字节的指令长度,前面12个字节用来填写跳转
ULONG_PTR GetWriteCodeLen(PVOID buffer)
{
	const char* const buffer_end = (char*)buffer + 45;

	nmd_x86_instruction instruction;
	char formatted_instruction[128];

	for (size_t i = 0; i < 45; i += instruction.length)
	{
		if (!nmd_decode_x86((char*)buffer + i, buffer_end - ((char*)buffer + i), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_MINIMAL))
			break;
#pragma warning(push)
#pragma warning(disable:4245)
		nmd_format_x86(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT);
#pragma warning(pop)
		if (i >= 12) return i;
	}

	return 0;
}

//通过物理地址，遍历HOOK信息链表，获取对应的HOOK信息
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr)
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return NULL;

	physAddr &= 0xFFFFFFFFFFFFF000;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);  // 获取EptHook链中Node基址
		if ((physAddr == pEntry->FakePagePhyAddr || physAddr == pEntry->RealPagePhyAddr) && physAddr)  // 对比找该函数HOOK信息
			return pEntry;
	}
	return NULL;
}

//同上，这里是虚拟地址
PEptHookInfo GetHookInfoByFunAddr(ULONG_PTR vaAddr)
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return NULL;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
		if (vaAddr == pEntry->OriginalFunAddr && vaAddr)
			return pEntry;
	}
	return NULL;
}

PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeFun)
{
	PVOID OriginalFunHeadCode = 0;
	/*
	跳到代理函数用
	push 代理地址
	ret
	的方式来HOOK

	跳到代理函数千万不能用jmp qword ptr [***]的方式，
	这样会读取该指令之后的地址(该指令之后的地址存储代理函数地址)
	导致不停触发EptViolation
	*/
	UCHAR JmpFakeAddr[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xC3";  // 12字节
	// mov rax,0; (\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00)     mov rax,xxxx(\x48\xB8)  一个\xXX是一个字节
	// push rax; (\x50)
	// ret; (\xC3)
	
	UCHAR JmpOriginalFun[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";  // 15字节
	// FF25 00000000	| jmp qword ptr ds:[7FF9A9E006BE]        
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |

	if (GetHookInfoByFunAddr(FunAddr)) return NULL;  // 查看函数是否被Hook过

	/*
	配置跳转的代码
	*/
	memcpy(JmpFakeAddr + 2, &FakeFun, 8);   // 这里相当于就是 mov rax,&FakeFun

	//配置跳回去的代码
	ULONG_PTR WriteLen = GetWriteCodeLen((PVOID)FunAddr);
	ULONG_PTR JmpOriginalAddr = FunAddr + WriteLen;
	memcpy(JmpOriginalFun + 6, &JmpOriginalAddr, 8);   // 从第一个FF| ? ? ? |开始填写

	//复制原函数页面
	ULONG_PTR fakePage = (ULONG_PTR)kmalloc(PAGE_SIZE);
	RtlCopyMemory((PVOID)fakePage, (PVOID)(FunAddr & 0xFFFFFFFFFFFFF000), PAGE_SIZE);//(PVOID)(FunAddr & 0xFFFFFFFFFFFFF000)取FunAddr所在PTE地址

	//保存原函数被修改的代码和跳回原函数
	OriginalFunHeadCode = kmalloc(WriteLen + 14);
	RtlFillMemory(OriginalFunHeadCode, WriteLen + 14, 0x90);
	memcpy(OriginalFunHeadCode, (PVOID)FunAddr, WriteLen);
	memcpy((PCHAR)(OriginalFunHeadCode)+WriteLen, JmpOriginalFun, 14);

	//配置用于执行的假页面
	ULONG_PTR offset = FunAddr - (FunAddr & 0xFFFFFFFFFFFFF000);
	RtlFillMemory((PVOID)(fakePage + offset), WriteLen, 0x90);
	memcpy((PVOID)(fakePage + offset), &JmpFakeAddr, 12);

	//初始化链表
	if (HidePageEntry.list.Flink == NULL) {
		InitializeListHead(&HidePageEntry.list);
	}

	//填写HOOK信息
	PEptHookInfo hidePage = (PEptHookInfo)kmalloc(sizeof(EptHookInfo));
	hidePage->FakePageVaAddr = fakePage;
	hidePage->FakePagePhyAddr = MmGetPhysicalAddress((PVOID)fakePage).QuadPart & 0xFFFFFFFFFFFFF000;
	hidePage->RealPagePhyAddr = MmGetPhysicalAddress((PVOID)(FunAddr & 0xFFFFFFFFFFFFF000)).QuadPart;
	hidePage->OriginalFunAddr = FunAddr;
	hidePage->OriginalFunHeadCode = (ULONG_PTR)OriginalFunHeadCode;

	//插入链表
	InsertTailList(&HidePageEntry.list, &hidePage->list);

	//VmCall，进入HOST操作EPT
	AsmVmxCall(CallEptHook, (ULONG_PTR)hidePage);

	return OriginalFunHeadCode;
}


VOID EptUnHOOK(ULONG_PTR FunAddr)
{
	PEptHookInfo hookInfo = GetHookInfoByFunAddr(FunAddr);
	if (!hookInfo) return;

	// 调用AsmVmxCall,由于调用约定是__fastcall,rcx存的是CallEptUnHook,rdx存的是hookInfo
	// AsmVmxCall内部直接调用产生VMEXIT回到Host的VmexitHandler进行分析原因派发
	// 派发到VmCallHandle中,VmCallHandle中取cx(也就是rcx低16Bit)进行于我们自定义的vmcall进行对比
	// 判断是不是EptUnHook,如果是则修复原页面
	AsmVmxCall(CallEptUnHook, (ULONG_PTR)hookInfo);

	kfree((PVOID)hookInfo->OriginalFunHeadCode);
	kfree((PVOID)hookInfo->FakePageVaAddr);
}


//销毁所有HOOK
VOID DestroyEptHook()
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
		EptUnHOOK(pEntry->OriginalFunAddr);
	}
}