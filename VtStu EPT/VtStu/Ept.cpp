#include"MyVT.h"

//一共要管理多大的内存
#define TOTAL_MEM 32

//指向整个EPT的指针
Eptp EptP = { 0 };
//分配的总内存的首地址
PCHAR EptMem = 0;
//有时候EPT并不是必须的，这里是是否启用EPT
BOOLEAN UseEpt = TRUE;

//通过物理地址获取对应的PTE
EptCommonEntry* GetPteByPhyAddr(ULONG_PTR addr)
{
	//根据9(PML4T) 9(PDPT) 9(PDT) 9(PT) 12(Page Offset) 分页获取各个表的下标
	ULONG_PTR PDPT_Index = (addr >> (9 + 9 + 12)) & 0x1FF; // 0x1FF=111111111
	ULONG_PTR PDT_Index = (addr >> (9 + 12)) & 0x1FF;
	ULONG_PTR PT_Index = (addr >> 12) & 0x1FF;

	//假设EptMem是一个每个元素是一页大小的数组，offset就是它的下标
	//求得每一等分大小,每一等分是一个PDT+512个PT,把一个PDT+512个PT看作一个单位,排除后两页(PML4T PDPT).
	ULONG_PTR offset = (TOTAL_MEM + TOTAL_MEM * 512) / 513;
	//得到目标等分下标，第一页是PDT，不要
	offset = offset * PDPT_Index + 1;
	//得到对应PT的下标
	offset = offset + PDT_Index;

	ULONG_PTR* PTE = (ULONG_PTR*)(EptMem + offset * PAGE_SIZE) + PT_Index;
	return (EptCommonEntry*)PTE;
}


BOOLEAN InitEpt()
{
	ULONG_PTR index = 0;
	ULONG_PTR* PML4T = 0, * PDPT = 0;

	//分配总的内存，其中2代表PML4T和PDPT需要的两页内存，TOTAL_MEM是PDT，TOTAL_MEM * 512是PT
	EptMem = (PCHAR)kmalloc((2 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE);
	if (!EptMem) return FALSE;

	//最后两页给PML4T和PDPT，这里类似一个每项大小为4KB的数组，第一项为(EptMem + 0 * PAGE_SIZE)
	//最后一项为(EptMem + (1 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE)
	PML4T = (ULONG_PTR*)(EptMem + (TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE);
	PDPT = (ULONG_PTR*)(EptMem + (1 + TOTAL_MEM + TOTAL_MEM * 512) * PAGE_SIZE);

	/*
	总的内存布局就是就是
	EptMem = {[PDT+512个PT],[PDT+512个PT],[PDT+512个PT]...共32个[PDT+512个PT]，PML4T，PDPT}
	*/

	// 加7表示可读可写可执行权限
	// PML4T[0]上存放的是指向一个PDPT的指针,这里实际上就把PML4T[0]指向这个PDPT并修改页面权限
	PML4T[0] = MmGetPhysicalAddress(PDPT).QuadPart + 7;
	for (ULONG_PTR PDPT_Index = 0; PDPT_Index < TOTAL_MEM; PDPT_Index++)
	{
		//分配一页给PDT
		ULONG_PTR* PDT = (ULONG_PTR*)(EptMem + PAGE_SIZE * index++);
		//初始化PDPTE,每一个PTDPTE指向一个PDT
		PDPT[PDPT_Index] = MmGetPhysicalAddress(PDT).QuadPart + 7;  // +7设置页面可读可写可执行

		for (ULONG_PTR PDT_Index = 0; PDT_Index < 512; PDT_Index++)
		{
			//分配一页给PT
			ULONG_PTR* PT = (ULONG_PTR*)(EptMem + PAGE_SIZE * index++);
			//初始化PDE，每一个PDE指向一个PT
			PDT[PDT_Index] = MmGetPhysicalAddress(PT).QuadPart + 7;  // +7设置页面可读可写可执行

			for (ULONG_PTR PT_Index = 0; PT_Index < 512; PT_Index++) //一个PTE地址8字节,4K/8=512个PTE,一个页表(PT)可存放512个物理页
			{
				//初始化PTE,每一个PT指向一个PTE(4K页面)
				PT[PT_Index] = (PDPT_Index * (1 << 30) + PDT_Index * (1 << 21) + PT_Index * (1 << 12) + 0x37);
				// EPT分页机制:   9				9			9			9			12
				//              PML4TIndex	 PDPTIndex	 PDTIndex     PTIndex     PageOffset
			}
		}
	}

	//IA32手册24.6.11, Intel 28.2.6 EPT and Memory Typing
	EptP.all = MmGetPhysicalAddress(PML4T).QuadPart + 7;  // EPTP指向PML4T,也就是第一个PML4E,+7修改权限

	// Intel A.10 VPID AND EPT CAPABILITIES
	//填0或6
	ULONGLONG memory_type = __readmsr(MsrVmxEptVpidCap);
	//跟二进制的100000000做与运算，看看第8位是否为1,为1可以填0，否则填6
	memory_type &= 0x100;
	EptP.fields.memory_type = memory_type ? 0 : 6;

	//使用的页表的级数-1，这里是9 9 9 9 12 分页共4级
	EptP.fields.page_walk_length = 3;

	return TRUE;
}
