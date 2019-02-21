#ifndef __DLLLOADER_H__
#define __DLLLOADER_H__

#include <windows.h>

#define FUNCCALLMODE __stdcall

#ifdef __cplusplus             
extern "C" {
#endif

	char* FUNCCALLMODE DLLMemLoad(char* DLLName);
	void  FUNCCALLMODE DLLMemFree(char* DLLMemBaseAddress);
	void* FUNCCALLMODE GetProcAddressByName(char* FunName);
	void* FUNCCALLMODE GetProcAddressByOrindal(short Orindal);


#ifdef __cplusplus
}
#endif


#endif