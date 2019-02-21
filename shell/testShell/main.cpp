#include <stdio.h>
#include <windows.h>
#include <Winternl.h>
#include "DLLLoader.h"

typedef char*  (__stdcall *lpDLLMemLoad)(char* DLLName);
typedef void  (__stdcall *lpDLLMemFree)(char* DLLMemBaseAddress);
typedef void* (__stdcall *lpGetProcAddressByName)(char* FunName);


typedef int(__stdcall *Add)(int, int);





int main()
{
	HINSTANCE hShell = LoadLibraryA("D:\\shell\\shell\\testShell\\shell.dll");
	if (hShell == NULL)
	{
		printf("%d\n", GetLastError());
		return -1;
	}

	lpDLLMemLoad MemLoad = (lpDLLMemLoad)GetProcAddress(hShell, "DLLMemLoad");
	lpDLLMemFree MemFree = (lpDLLMemFree)GetProcAddress(hShell, "DLLMemFree");
	lpGetProcAddressByName MemGet = (lpGetProcAddressByName)GetProcAddress(hShell, "GetProcAddressByName");


	if (MemLoad == NULL && MemFree == NULL && MemGet == NULL)
	{
		return -1;
	}

	char* hMoudle = MemLoad("testDll2.dll");
	Add add = (Add)MemGet("add");
	printf("%d\n", add(1, 2));
	MemFree(hMoudle);
	getchar();

	return 0;
}
