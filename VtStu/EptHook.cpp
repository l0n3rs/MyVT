#include "HOOK.h"
#include "nmd_assembly.h"

EptHookInfo HidePageEntry = { 0 };
PSYSTEM_SERVICE_TABLE SsdtAddr = 0;

UINT64 GetSSDT()
{
	// IA32_LSTAR��0xC0000082������ģʽ��Long Mode����64λ���£�SYSCALL���ں�RIP���Ѱַ��
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
			// //ʹ��MmIsAddressValid()��������ַ�Ƿ���ҳ����󣬵���΢��������ʹ�ô˺���
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
		//�Ա�����ֵ
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

	PULONG lpBase = (PULONG)SsdtAddr->ServiceTableBase;  // ϵͳ��������
	ULONG dwCount = (ULONG)SsdtAddr->NumberOfServices;   // ���������
	UINT64 lpAddr = 0;
	ULONG dwOffset = lpBase[dwIndex];					 // X64��ServiceTableBase��ŵ���SSDT���������ServiceTableBase��ƫ�� * 0x10��ֵ

	if (dwIndex >= dwCount) return NULL;				 // �����У��

	if (dwOffset & 0x80000000)							 // 0x80000000=1��63��0
		// ��������,������λΪ1�������ƺ����λ��Ҫ��1����1�����λ�ٴ���1���ٴ����ƺ����λ��Ȼ��Ҫ��1��
		// ������������λ������Ҫ���Ĵζ����Ƶ�1��0x1111��Ϊ0XF�������λ��F
		dwOffset = (dwOffset >> 4) | 0xF0000000;  // >>4�ǳ�ȥ0x10ȡ��������ƫ��
	else
		dwOffset >>= 4; // >>4�ǳ�ȥ0x10ȡ��������ƫ��
	lpAddr = (UINT64)((PUCHAR)lpBase + (LONG)dwOffset);  // ƫ��+��ַ���ɵõ��ú����ĵ�ַ
	return lpAddr;
}

//��ȡ>=12���ֽڵ�ָ���,ǰ��12���ֽ�������д��ת
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

//ͨ�������ַ������HOOK��Ϣ������ȡ��Ӧ��HOOK��Ϣ
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr)
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return NULL;

	physAddr &= 0xFFFFFFFFFFFFF000;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);  // ��ȡEptHook����Node��ַ
		if ((physAddr == pEntry->FakePagePhyAddr || physAddr == pEntry->RealPagePhyAddr) && physAddr)  // �Ա��Ҹú���HOOK��Ϣ
			return pEntry;
	}
	return NULL;
}

//ͬ�ϣ������������ַ
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
	������������
	push �����ַ
	ret
	�ķ�ʽ��HOOK

	����������ǧ������jmp qword ptr [***]�ķ�ʽ��
	�������ȡ��ָ��֮��ĵ�ַ(��ָ��֮��ĵ�ַ�洢��������ַ)
	���²�ͣ����EptViolation
	*/
	UCHAR JmpFakeAddr[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xC3";  // 12�ֽ�
	// mov rax,0; (\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00)     mov rax,xxxx(\x48\xB8)  һ��\xXX��һ���ֽ�
	// push rax; (\x50)
	// ret; (\xC3)
	
	UCHAR JmpOriginalFun[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";  // 15�ֽ�
	// FF25 00000000	| jmp qword ptr ds:[7FF9A9E006BE]        
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |
	// FF				| ? ? ? |

	if (GetHookInfoByFunAddr(FunAddr)) return NULL;  // �鿴�����Ƿ�Hook��

	/*
	������ת�Ĵ���
	*/
	memcpy(JmpFakeAddr + 2, &FakeFun, 8);   // �����൱�ھ��� mov rax,&FakeFun

	//��������ȥ�Ĵ���
	ULONG_PTR WriteLen = GetWriteCodeLen((PVOID)FunAddr);
	ULONG_PTR JmpOriginalAddr = FunAddr + WriteLen;
	memcpy(JmpOriginalFun + 6, &JmpOriginalAddr, 8);   // �ӵ�һ��FF| ? ? ? |��ʼ��д

	//����ԭ����ҳ��
	ULONG_PTR fakePage = (ULONG_PTR)kmalloc(PAGE_SIZE);
	RtlCopyMemory((PVOID)fakePage, (PVOID)(FunAddr & 0xFFFFFFFFFFFFF000), PAGE_SIZE);//(PVOID)(FunAddr & 0xFFFFFFFFFFFFF000)ȡFunAddr����PTE��ַ

	//����ԭ�������޸ĵĴ��������ԭ����
	OriginalFunHeadCode = kmalloc(WriteLen + 14);
	RtlFillMemory(OriginalFunHeadCode, WriteLen + 14, 0x90);
	memcpy(OriginalFunHeadCode, (PVOID)FunAddr, WriteLen);
	memcpy((PCHAR)(OriginalFunHeadCode)+WriteLen, JmpOriginalFun, 14);

	//��������ִ�еļ�ҳ��
	ULONG_PTR offset = FunAddr - (FunAddr & 0xFFFFFFFFFFFFF000);
	RtlFillMemory((PVOID)(fakePage + offset), WriteLen, 0x90);
	memcpy((PVOID)(fakePage + offset), &JmpFakeAddr, 12);

	//��ʼ������
	if (HidePageEntry.list.Flink == NULL) {
		InitializeListHead(&HidePageEntry.list);
	}

	//��дHOOK��Ϣ
	PEptHookInfo hidePage = (PEptHookInfo)kmalloc(sizeof(EptHookInfo));
	hidePage->FakePageVaAddr = fakePage;
	hidePage->FakePagePhyAddr = MmGetPhysicalAddress((PVOID)fakePage).QuadPart & 0xFFFFFFFFFFFFF000;
	hidePage->RealPagePhyAddr = MmGetPhysicalAddress((PVOID)(FunAddr & 0xFFFFFFFFFFFFF000)).QuadPart;
	hidePage->OriginalFunAddr = FunAddr;
	hidePage->OriginalFunHeadCode = (ULONG_PTR)OriginalFunHeadCode;

	//��������
	InsertTailList(&HidePageEntry.list, &hidePage->list);

	//VmCall������HOST����EPT
	AsmVmxCall(CallEptHook, (ULONG_PTR)hidePage);

	return OriginalFunHeadCode;
}


VOID EptUnHOOK(ULONG_PTR FunAddr)
{
	PEptHookInfo hookInfo = GetHookInfoByFunAddr(FunAddr);
	if (!hookInfo) return;

	// ����AsmVmxCall,���ڵ���Լ����__fastcall,rcx�����CallEptUnHook,rdx�����hookInfo
	// AsmVmxCall�ڲ�ֱ�ӵ��ò���VMEXIT�ص�Host��VmexitHandler���з���ԭ���ɷ�
	// �ɷ���VmCallHandle��,VmCallHandle��ȡcx(Ҳ����rcx��16Bit)�����������Զ����vmcall���жԱ�
	// �ж��ǲ���EptUnHook,��������޸�ԭҳ��
	AsmVmxCall(CallEptUnHook, (ULONG_PTR)hookInfo);

	kfree((PVOID)hookInfo->OriginalFunHeadCode);
	kfree((PVOID)hookInfo->FakePageVaAddr);
}


//��������HOOK
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