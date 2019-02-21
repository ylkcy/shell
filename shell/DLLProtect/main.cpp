#include <string>
#include <iostream>
#include <windows.h>
#include "CheckSum.h"
#include "AES.h"
#include "ZlibSdk.h"
#include "log.h"


using namespace std;

#pragma warning (disable: 4275)
#define offset(a, b) ((DWORD)((char*)(b) - (char*)(a)))

//用于保存加密信息
typedef struct DllInfo
{
	DWORD dwCRC32; //用于校验文件的完整性, 计算IMAGE_DOS_HEADER的大小
	BYTE  szAESKey[16]; //AES key
}DllInfo;

//获取本机的CPUID
DWORD GetCPUID()
{
	DWORD dwResult = 0;

	__asm
	{
		PUSHAD
		MOV EAX, 1
		MOV ECX, 0
		CPUID
		MOV dwResult, ECX
		POPAD
	}

	return dwResult;
}
//判断是否为有效的PE文件
bool isValidPE(BYTE* SrcDLLFileBuf)
{
	//MZ标记
	if(SrcDLLFileBuf == NULL)
	{
		return false;
	}
	BYTE* lpFileBuf = SrcDLLFileBuf;
	if(lpFileBuf[0] != 'M' || lpFileBuf[1] != 'Z')
	{
		return false;
	}
	IMAGE_DOS_HEADER *lpDOSHeader = (IMAGE_DOS_HEADER *)SrcDLLFileBuf;//DOS头
	IMAGE_NT_HEADERS *lpNTHeaders = (IMAGE_NT_HEADERS *)((DWORD)SrcDLLFileBuf + lpDOSHeader->e_lfanew);//NT头
	//PE标记
	lpFileBuf = (BYTE*)lpNTHeaders;
	if(lpFileBuf[0] != 'P' || lpFileBuf[1] != 'E')
	{
		return false;
	}
	return true;
}

//打开文件,读取文件内容,需在外部释放内存
BYTE* PeOpenFile(char* FileName, DWORD* dwSrcFileSize)
{
	DWORD dwResult = 0;
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LOG("%s文件打开失败%d\n", FileName, ERRORCODE);
		return NULL;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);//获取DLL文件大小
	if (dwFileSize == 0xFFFFFFFFF)
	{
		LOG("%s获取文件大小失败%d\n", FileName, ERRORCODE);
		return NULL;
	}
	*dwSrcFileSize = dwFileSize;
	BYTE* lpFileBuf = new BYTE[dwFileSize];
	if (lpFileBuf == NULL)
	{
		return NULL;
	}
	memset(lpFileBuf, 0, sizeof(lpFileBuf));
	DWORD dwReadSize = 0;
	dwResult = ReadFile(hFile, lpFileBuf, dwFileSize, &dwReadSize, NULL);//读入DLL文件
	if (dwResult == 0 || dwFileSize != dwReadSize)
	{
		LOG("文件读取失败:%d\n", ERRORCODE);
		return NULL;
	}
	CloseHandle(hFile);

	return lpFileBuf;
}

void PeWriteFile(char* FileName, BYTE* lpZipStr, DWORD dwZipFileSize)
{
	HANDLE hDstFile = CreateFileA(FileName, GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDstFile == INVALID_HANDLE_VALUE)
	{
		LOG("hDstFile open Fail!\n");
		exit(1);
	}
	//待写入 = 压缩后大小 + DWORD(记录文件大小)
	DWORD dwNumberOfBytesToWrite = dwZipFileSize + 4;
	DWORD dwWriteSize = 0;
	WriteFile(hDstFile, lpZipStr, dwNumberOfBytesToWrite, &dwWriteSize, NULL);
	LOG("WriteSize: %d\n", dwWriteSize);
	CloseHandle(hDstFile);
}

//对数据进行加密,压缩. 需在外部释放内存
BYTE* Encrypt(BYTE* lpSrcFileBuf, DWORD dwSrcFileSize, DWORD* dwZipSize)
{
	IMAGE_DOS_HEADER *File_DOS_Header = (IMAGE_DOS_HEADER *)lpSrcFileBuf;//DOS头
	IMAGE_NT_HEADERS *File_NT_Headers = (IMAGE_NT_HEADERS *)((DWORD)lpSrcFileBuf + File_DOS_Header->e_lfanew);//NT头
	//声明一个DLLInfo结构体,用于加密信息,写入PE文件头部空闲数据
	DllInfo dllInfo;
	memset(&dllInfo, 0, sizeof(DllInfo));
	//获取CRC32 从PE标记处开始 防止导入表导出表等被修改
	dllInfo.dwCRC32 = get_crc32((unsigned char*)(lpSrcFileBuf + File_DOS_Header->e_lfanew), sizeof(IMAGE_NT_HEADERS));
	LOG("CRC32: %0x\n", dllInfo.dwCRC32);
	//获取AES key
	DWORD dwCPUID = GetCPUID();
	sprintf((char*)dllInfo.szAESKey, "%0x", dwCPUID);
	LOG("Key: %s\n", dllInfo.szAESKey);

	//将结构体写入PE DOS sub中
	DWORD dwOffset = offset((DWORD)File_DOS_Header + sizeof(IMAGE_DOS_HEADER), File_NT_Headers);
	//空间是否足够
	if (dwOffset < sizeof(DllInfo))
	{
		LOG("NT与DOS偏移:%d\n", dwOffset);
		return NULL;
	}
	//在DOS头后写入加密信息
	CopyMemory(lpSrcFileBuf + sizeof(IMAGE_DOS_HEADER), &dllInfo, sizeof(DllInfo));

	//加密缓冲区
	BYTE* lpEncryptStr = new BYTE[dwSrcFileSize];
	if (lpEncryptStr == NULL)
	{
		LOG("malloc fail\n");
		return NULL;
	}
	memset(lpEncryptStr, 0, sizeof(lpEncryptStr));

	//对写入之后的数据进行加密
	Botan::SecureVector<Botan::byte> vector_in(lpSrcFileBuf, dwSrcFileSize);
	Botan::SecureVector<Botan::byte> vector_out(lpEncryptStr, dwSrcFileSize);

	CryptoAES128(vector_in, (char*)dllInfo.szAESKey, Botan::Cipher_Dir::ENCRYPTION, vector_out);

	if (lpEncryptStr != NULL)
	{
		delete[] lpEncryptStr;
		lpEncryptStr = NULL;
	}

#if 0
	//CFB算法模式加密和解密后,明文与密文的长度一致
	BYTE* lpDecryptStr = new BYTE[dwSrcFileSize];
	if (lpDecryptStr == NULL)
	{
		LOG("malloc fail\n");
		exit(1);
	}

	memset(lpDecryptStr, 0, dwSrcFileSize);
	Botan::SecureVector<Botan::byte> vector_out2(lpDecryptStr, dwSrcFileSize);
	CryptoAES128(vector_out, (char*)dllInfo.szAESKey, Botan::Cipher_Dir::DECRYPTION, vector_out2);

	if (vector_in == vector_out2)
	{
		LOG("OK\n");
	}
	else
	{
		LOG("ERROR\n");
	}

	if (lpDecryptStr != NULL)
	{
		delete[] lpEncryptStr;
		lpDecryptStr = NULL;
	}
#endif

	ZLibSDk zsdk;
	if (zsdk.LoadDllStatus() != 0)
	{
		LOG("加载DLL失败\n");
		return NULL;
	}
	/*
	Compresses the source buffer into the destination buffer. The level
	parameter has the same meaning as in deflateInit.  sourceLen is the byte
	length of the source buffer. Upon entry, destLen is the total size of the
	destination buffer, which must be at least 0.1% larger than sourceLen plus
	12 bytes. Upon exit, destLen is the actual size of the compressed buffer.
	return code Z_BUF_ERROR(-5):表示没有足够的输出缓冲区   Z_MEM_ERROR(-4)：表示没有足够的内存  Z_OK(0):成功！
	*/
	//获取压缩需要分配空间的大小
	DWORD dwMallocSize = zsdk.compressbound(dwSrcFileSize);
	LOG("dwMallocSize:%d\n", dwMallocSize);
	//预留四字节保留原始文件的大小
	BYTE* lpZipStr = new BYTE[dwMallocSize + sizeof(DWORD)];
	if (lpZipStr == NULL)
	{
		LOG("malloc fail\n");
		return NULL;
	}
	memset(lpZipStr, 0, sizeof(lpZipStr));
	*(DWORD*)lpZipStr = dwSrcFileSize;
	//对加密之后的数据进行压缩
	int iRet = zsdk.compress(lpZipStr + 4, &dwMallocSize, vector_out.data(), dwSrcFileSize);
	if (iRet != Z_OK)
	{
		LOG("解压失败\n");
		return NULL;
	}
	LOG("iret:%d\n", iRet);
	LOG("压缩前大小: %d, 压缩后大小 : %d\n", dwSrcFileSize, dwMallocSize);
	*dwZipSize = dwMallocSize;
	return lpZipStr;
}


int main(int argc, char* argv[])
{
	Botan::LibraryInitializer init;
	if (argc != 3)
	{
		printf("Usage: %s <pe-srcfilename-dstfilename>\n", argv[0]);
		exit(1);
	}

	DWORD dwSrcFileSize = 0;
	BYTE* lpSrcFileBuf = NULL;
	lpSrcFileBuf = PeOpenFile(argv[1], &dwSrcFileSize);
	if (lpSrcFileBuf == NULL)
	{
		LOG("文件操作失败\n");
		exit(1);
	}

	if(!isValidPE(lpSrcFileBuf))
	{
		LOG("无效的PE文件\n");
		exit(1);
	}
	DWORD dwZipFileSize = 0;
	BYTE* lpZipFileBuf = NULL;
	lpZipFileBuf = Encrypt(lpSrcFileBuf, dwSrcFileSize, &dwZipFileSize);
	if (lpZipFileBuf == NULL)
	{
		LOG("文件加密失败\n");
		exit(1);
	}

	PeWriteFile(argv[2], lpZipFileBuf, dwZipFileSize);
	
	if (lpSrcFileBuf != NULL)
	{
		delete[] lpSrcFileBuf;
		lpSrcFileBuf = NULL;
	}
	if (lpZipFileBuf != NULL)
	{
		delete[] lpZipFileBuf;
		lpZipFileBuf = NULL;
	}
	
	
	return 0;
}



