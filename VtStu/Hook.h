#pragma once

#include"MyVT.h"

//���ڱ���HOOK��Ϣ������
typedef struct _EptHookInfo
{
	ULONG_PTR RealPagePhyAddr;

	ULONG_PTR FakePagePhyAddr;
	ULONG_PTR FakePageVaAddr;

	ULONG_PTR OriginalFunAddr;
	ULONG_PTR OriginalFunHeadCode;

	LIST_ENTRY list;
} EptHookInfo, * PEptHookInfo;

// SSDT�Ľṹ
typedef struct _SYSTEM_SERVICE_TABLE {
	PLONG  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


extern PSYSTEM_SERVICE_TABLE SsdtAddr;

//��ȡSSDT
UINT64 GetSSDT();
//ͨ��SSDT�õ�������ַ
UINT64 GetSsdtFunAddr(ULONG dwIndex);

//ͨ�������ַ�õ�HOOK��Ϣ
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr);
//ͨ�����������ַ�õ�HOOK��Ϣ
PEptHookInfo GetHookInfoByFunAddr(ULONG_PTR vaAddr);

PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeAddr);
VOID EptUnHOOK(ULONG_PTR FunAddr);
VOID DestroyEptHook();


EXTERN_C VOID HookTest();