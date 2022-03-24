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
	int cupIndex;   // CPU�±�
	BOOLEAN isEnable;   // ��ǰ��CPU�Ƿ��Ѿ��ɹ�����VT
	BOOLEAN StartVT();       // ����VT
	MyVT(int cupIndex);
	~MyVT();
private:
	// VMX ������Ҫ���ڱ���host��һЩ������Ϣ,�������ʹ������ڴ����ǲ���Ҫ����,ֻ��Ҫ����һҳ�ڴ������CPU����
	ULONG_PTR VMX_Region;   // VMX�ڴ�����

	// Virtual-Machine Control Structure,�������������������ƽṹ,������д�������ø��������������Ϣ,�������ض�дMSR,��дCR3�ȵ�
	ULONG_PTR VMCS_Region;  // VMCS�ڴ�����

	// ���Ҫ����Msr��д,��Ҫ�������
	ULONG_PTR MsrBitmap;    // MSRBitMap�ڴ�����

	// Host����ʱ��ջ�ռ�
	PCHAR VmmStack;         // VMMStack�ڴ�����,Hostʹ��

	BOOLEAN ExecuteVMXON();  // ִ��VMXON

	BOOLEAN InitVMCS(PVOID guestStack, PVOID guestResumeRip);
};


//���ڻ�ȡC++�����Ա������ַ
typedef union
{
	PVOID addr;
	BOOLEAN(MyVT::* fun)(PVOID, PVOID);
} FunAddr;