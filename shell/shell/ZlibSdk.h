#ifndef _ZLIB_SDK_H
#define _ZLIB_SDK_H
#include "zlib.h"
#include <windows.h>


class ZLibSDk
{
	typedef int(__stdcall *fun)(Bytef*, uLongf*, const Bytef*, uLongf);
public:
	ZLibSDk();
	~ZLibSDk();
	int LoadDllStatus();
	int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
	int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
public:
	fun lpCompress,lpUnCompress; 
private:
	HINSTANCE m_API;
};


#endif