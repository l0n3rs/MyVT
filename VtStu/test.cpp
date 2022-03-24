#include"HOOK.h"

typedef NTSTATUS(*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);


pNtOpenProcess OriginalNtOpenProcess = NULL;
int index = 0;

//������
NTSTATUS MyNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	if ((index % 1000) == 0) {
		Log("HOOK NtOpenProcess ���ô���: %d", index);
	}
	index++;
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//����HOOK NtOpenProcess
//EptHOOK(ԭ������ַ, ��������ַ)
EXTERN_C VOID HookTest()
{
	OriginalNtOpenProcess = (pNtOpenProcess)EptHOOK(GetSsdtFunAddr(38), MyNtOpenProcess);
}