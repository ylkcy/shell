#ifndef _TEST_DLL_H
#define _TEST_DLL_H

#define FUNCCALLMODE __stdcall

#ifdef __cplusplus             
extern "C" {
#endif

int FUNCCALLMODE add(int a, int b);
int FUNCCALLMODE sub(int a, int b);
int FUNCCALLMODE mul(int a, int b);
int FUNCCALLMODE div(int a, int b);

#ifdef __cplusplus
}
#endif


#endif