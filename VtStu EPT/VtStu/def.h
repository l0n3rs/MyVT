#pragma once

// 主要用于存放一些公共的函数或者结构体
#include<ntifs.h>
#include<intrin.h>
#include"ia32.h"

#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"[VT]: " format "\n",##__VA_ARGS__)

#define VMM_STACK_SIZE 10*PAGE_SIZE



EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);


EXTERN_C
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);


EXTERN_C
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

// 检测CPU是否支持VT
BOOLEAN CheckVTSupport();
// 检测主板是否支持VT
BOOLEAN CheckVTEnable();


_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t size);

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, SIZE_T size);


PVOID kmalloc(ULONG_PTR size);
VOID kfree(PVOID p);