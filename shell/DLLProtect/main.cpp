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

//���ڱ��������Ϣ
typedef struct DllInfo
{
	DWORD dwCRC32; //����У���ļ���������, ����IMAGE_DOS_HEADER�Ĵ�С
	BYTE  szAESKey[16]; //AES key
}DllInfo;

//��ȡ������CPUID
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
//�ж��Ƿ�Ϊ��Ч��PE�ļ�
bool isValidPE(BYTE* SrcDLLFileBuf)
{
	//MZ���
	if(SrcDLLFileBuf == NULL)
	{
		return false;
	}
	BYTE* lpFileBuf = SrcDLLFileBuf;
	if(lpFileBuf[0] != 'M' || lpFileBuf[1] != 'Z')
	{
		return false;
	}
	IMAGE_DOS_HEADER *lpDOSHeader = (IMAGE_DOS_HEADER *)SrcDLLFileBuf;//DOSͷ
	IMAGE_NT_HEADERS *lpNTHeaders = (IMAGE_NT_HEADERS *)((DWORD)SrcDLLFileBuf + lpDOSHeader->e_lfanew);//NTͷ
	//PE���
	lpFileBuf = (BYTE*)lpNTHeaders;
	if(lpFileBuf[0] != 'P' || lpFileBuf[1] != 'E')
	{
		return false;
	}
	return true;
}

//���ļ�,��ȡ�ļ�����,�����ⲿ�ͷ��ڴ�
BYTE* PeOpenFile(char* FileName, DWORD* dwSrcFileSize)
{
	DWORD dwResult = 0;
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LOG("%s�ļ���ʧ��%d\n", FileName, ERRORCODE);
		return NULL;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);//��ȡDLL�ļ���С
	if (dwFileSize == 0xFFFFFFFFF)
	{
		LOG("%s��ȡ�ļ���Сʧ��%d\n", FileName, ERRORCODE);
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
	dwResult = ReadFile(hFile, lpFileBuf, dwFileSize, &dwReadSize, NULL);//����DLL�ļ�
	if (dwResult == 0 || dwFileSize != dwReadSize)
	{
		LOG("�ļ���ȡʧ��:%d\n", ERRORCODE);
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
	//��д�� = ѹ�����С + DWORD(��¼�ļ���С)
	DWORD dwNumberOfBytesToWrite = dwZipFileSize + 4;
	DWORD dwWriteSize = 0;
	WriteFile(hDstFile, lpZipStr, dwNumberOfBytesToWrite, &dwWriteSize, NULL);
	LOG("WriteSize: %d\n", dwWriteSize);
	CloseHandle(hDstFile);
}

//�����ݽ��м���,ѹ��. �����ⲿ�ͷ��ڴ�
BYTE* Encrypt(BYTE* lpSrcFileBuf, DWORD dwSrcFileSize, DWORD* dwZipSize)
{
	IMAGE_DOS_HEADER *File_DOS_Header = (IMAGE_DOS_HEADER *)lpSrcFileBuf;//DOSͷ
	IMAGE_NT_HEADERS *File_NT_Headers = (IMAGE_NT_HEADERS *)((DWORD)lpSrcFileBuf + File_DOS_Header->e_lfanew);//NTͷ
	//����һ��DLLInfo�ṹ��,���ڼ�����Ϣ,д��PE�ļ�ͷ����������
	DllInfo dllInfo;
	memset(&dllInfo, 0, sizeof(DllInfo));
	//��ȡCRC32 ��PE��Ǵ���ʼ ��ֹ���������ȱ��޸�
	dllInfo.dwCRC32 = get_crc32((unsigned char*)(lpSrcFileBuf + File_DOS_Header->e_lfanew), sizeof(IMAGE_NT_HEADERS));
	LOG("CRC32: %0x\n", dllInfo.dwCRC32);
	//��ȡAES key
	DWORD dwCPUID = GetCPUID();
	sprintf((char*)dllInfo.szAESKey, "%0x", dwCPUID);
	LOG("Key: %s\n", dllInfo.szAESKey);

	//���ṹ��д��PE DOS sub��
	DWORD dwOffset = offset((DWORD)File_DOS_Header + sizeof(IMAGE_DOS_HEADER), File_NT_Headers);
	//�ռ��Ƿ��㹻
	if (dwOffset < sizeof(DllInfo))
	{
		LOG("NT��DOSƫ��:%d\n", dwOffset);
		return NULL;
	}
	//��DOSͷ��д�������Ϣ
	CopyMemory(lpSrcFileBuf + sizeof(IMAGE_DOS_HEADER), &dllInfo, sizeof(DllInfo));

	//���ܻ�����
	BYTE* lpEncryptStr = new BYTE[dwSrcFileSize];
	if (lpEncryptStr == NULL)
	{
		LOG("malloc fail\n");
		return NULL;
	}
	memset(lpEncryptStr, 0, sizeof(lpEncryptStr));

	//��д��֮������ݽ��м���
	Botan::SecureVector<Botan::byte> vector_in(lpSrcFileBuf, dwSrcFileSize);
	Botan::SecureVector<Botan::byte> vector_out(lpEncryptStr, dwSrcFileSize);

	CryptoAES128(vector_in, (char*)dllInfo.szAESKey, Botan::Cipher_Dir::ENCRYPTION, vector_out);

	if (lpEncryptStr != NULL)
	{
		delete[] lpEncryptStr;
		lpEncryptStr = NULL;
	}

#if 0
	//CFB�㷨ģʽ���ܺͽ��ܺ�,���������ĵĳ���һ��
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
		LOG("����DLLʧ��\n");
		return NULL;
	}
	/*
	Compresses the source buffer into the destination buffer. The level
	parameter has the same meaning as in deflateInit.  sourceLen is the byte
	length of the source buffer. Upon entry, destLen is the total size of the
	destination buffer, which must be at least 0.1% larger than sourceLen plus
	12 bytes. Upon exit, destLen is the actual size of the compressed buffer.
	return code Z_BUF_ERROR(-5):��ʾû���㹻�����������   Z_MEM_ERROR(-4)����ʾû���㹻���ڴ�  Z_OK(0):�ɹ���
	*/
	//��ȡѹ����Ҫ����ռ�Ĵ�С
	DWORD dwMallocSize = zsdk.compressbound(dwSrcFileSize);
	LOG("dwMallocSize:%d\n", dwMallocSize);
	//Ԥ�����ֽڱ���ԭʼ�ļ��Ĵ�С
	BYTE* lpZipStr = new BYTE[dwMallocSize + sizeof(DWORD)];
	if (lpZipStr == NULL)
	{
		LOG("malloc fail\n");
		return NULL;
	}
	memset(lpZipStr, 0, sizeof(lpZipStr));
	*(DWORD*)lpZipStr = dwSrcFileSize;
	//�Լ���֮������ݽ���ѹ��
	int iRet = zsdk.compress(lpZipStr + 4, &dwMallocSize, vector_out.data(), dwSrcFileSize);
	if (iRet != Z_OK)
	{
		LOG("��ѹʧ��\n");
		return NULL;
	}
	LOG("iret:%d\n", iRet);
	LOG("ѹ��ǰ��С: %d, ѹ�����С : %d\n", dwSrcFileSize, dwMallocSize);
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
		LOG("�ļ�����ʧ��\n");
		exit(1);
	}

	if(!isValidPE(lpSrcFileBuf))
	{
		LOG("��Ч��PE�ļ�\n");
		exit(1);
	}
	DWORD dwZipFileSize = 0;
	BYTE* lpZipFileBuf = NULL;
	lpZipFileBuf = Encrypt(lpSrcFileBuf, dwSrcFileSize, &dwZipFileSize);
	if (lpZipFileBuf == NULL)
	{
		LOG("�ļ�����ʧ��\n");
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



