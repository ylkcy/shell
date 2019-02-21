#include "ZlibSdk.h"


ZLibSDk::ZLibSDk()
{
	m_API = LoadLibraryA("zlibwapi.dll");
	if (m_API == NULL)
	{
		return;
	}
	lpCompress = (fun)GetProcAddress(m_API, "compress");
	lpUnCompress = (fun)GetProcAddress(m_API, "uncompress");
}


ZLibSDk::~ZLibSDk()
{
	if (m_API != NULL)
	{
		FreeLibrary(m_API);
		m_API = NULL;
	}
} 

int ZLibSDk::LoadDllStatus()
{
	if (m_API == NULL)
	{
		return -1;
	}
	if (lpUnCompress && lpCompress)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}


int ZLibSDk::compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
{
	return lpCompress(dest, destLen, source, sourceLen);
}


int ZLibSDk::uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
{
	return lpUnCompress(dest, destLen, source, sourceLen);
}