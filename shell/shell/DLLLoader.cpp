#include "DLLLoader.h"
#include "log.h"
#include "AES.h"
#include "ZlibSdk.h"
#include "CheckSum.h"


typedef struct DllInfo
{
	DWORD dwCRC32; //����У���ļ���������, ����IMAGE_DOS_HEADER�Ĵ�С
	char  szAESKey[16]; //AES key
}DllInfo;

typedef struct _PEB 
{ // Size: 0x1D8  
	/*000*/ UCHAR InheritedAddressSpace;  
	/*001*/ UCHAR ReadImageFileExecOptions;  
	/*002*/ UCHAR BeingDebugged;  //IsDebuggerPresent() �����Ƿ��ڵ���״̬
	/*003*/ UCHAR SpareBool;  
	/*004*/ HANDLE Mutant;  
	/*008*/ DWORD ImageBaseAddress; // ImageBase 
	/*00C*/ DWORD DllList;          //��DLL���ص����̣��ɴ� PEB.Ldr�л�ȡ��ģ��Ļ�ַ��������Ϣ  
	/*010*/ DWORD ProcessParameters;  
	/*014*/ ULONG SubSystemData;  
	/*018*/ HANDLE DefaultHeap;  
	/*01C*/ KSPIN_LOCK FastPebLock;  
	/*020*/ ULONG FastPebLockRoutine;  
	/*024*/ ULONG FastPebUnlockRoutine;  
	/*028*/ ULONG EnvironmentUpdateCount;  
	/*02C*/ ULONG KernelCallbackTable;  
	/*030*/ LARGE_INTEGER SystemReserved;  
	/*038*/ ULONG FreeList;  
	/*03C*/ ULONG TlsExpansionCounter;  
	/*040*/ ULONG TlsBitmap;  
	/*044*/ LARGE_INTEGER TlsBitmapBits;  
	/*04C*/ ULONG ReadOnlySharedMemoryBase;  
	/*050*/ ULONG ReadOnlySharedMemoryHeap;  
	/*054*/ ULONG ReadOnlyStaticServerData;  
	/*058*/ ULONG AnsiCodePageData;  
	/*05C*/ ULONG OemCodePageData;  
	/*060*/ ULONG UnicodeCaseTableData;  
	/*064*/ ULONG NumberOfProcessors;  
	/*068*/ LARGE_INTEGER NtGlobalFlag;   
	/*070*/ LARGE_INTEGER CriticalSectionTimeout;  
	/*078*/ ULONG HeapSegmentReserve;  
	/*07C*/ ULONG HeapSegmentCommit;  
	/*080*/ ULONG HeapDeCommitTotalFreeThreshold;  
	/*084*/ ULONG HeapDeCommitFreeBlockThreshold;  
	/*088*/ ULONG NumberOfHeaps;  
	/*08C*/ ULONG MaximumNumberOfHeaps;  
	/*090*/ ULONG ProcessHeaps;  
	/*094*/ ULONG GdiSharedHandleTable;  
	/*098*/ ULONG ProcessStarterHelper;  
	/*09C*/ ULONG GdiDCAttributeList;  
	/*0A0*/ KSPIN_LOCK LoaderLock;  
	/*0A4*/ ULONG OSMajorVersion;  
	/*0A8*/ ULONG OSMinorVersion;  
	/*0AC*/ USHORT OSBuildNumber;  
	/*0AE*/ USHORT OSCSDVersion;  
	/*0B0*/ ULONG OSPlatformId;  
	/*0B4*/ ULONG ImageSubsystem;  
	/*0B8*/ ULONG ImageSubsystemMajorVersion;  
	/*0BC*/ ULONG ImageSubsystemMinorVersion;  
	/*0C0*/ ULONG ImageProcessAffinityMask;  
	/*0C4*/ ULONG GdiHandleBuffer[0x22];  
	/*14C*/ ULONG PostProcessInitRoutine;  
	/*150*/ ULONG TlsExpansionBitmap;  
	/*154*/ UCHAR TlsExpansionBitmapBits[0x80];  
	/*1D4*/ ULONG SessionId;  
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA  
{  
	ULONG Length; // +0x00  
	BOOLEAN Initialized; // +0x04  
	PVOID SsHandle; // +0x08  
	LIST_ENTRY InLoadOrderModuleList; // +0x0c 
	LIST_ENTRY InMemoryOrderModuleList; // +0x14  
	LIST_ENTRY InInitializationOrderModuleList;// +0x1c  
} PEB_LDR_DATA,*PPEB_LDR_DATA; // +0x24

typedef struct _UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING,*PUNICODE_STRING;

typedef enum __PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority, // invalid for query
	ProcessRaisePriority, // invalid for query
	ProcessDebugPort,
	ProcessExceptionPort, // invalid for query
	ProcessAccessToken, // invalid for query
	ProcessLdtInformation,
	ProcessLdtSize, // invalid for query
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only, invalid for query
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL, // invalid class
	ProcessEnableAlignmentFaultFixup, // invalid class
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask, // invalid for query
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation, // invalid for query
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags, // EProcess->Flags.NoDebugInherit
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation, // invalid class
	ProcessCookie,
	ProcessImageInformation, // last available on XPSP3
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback, // invalid class
	ProcessThreadStackAllocation, // invalid class
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32, // buffer is a UNICODE_STRING
	ProcessImageFileMapping, // buffer is a pointer to a file handle open with SYNCHRONIZE | FILE_EXECUTE access, return value is whether the handle is the same used to start the process
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled, // invalid class
	ProcessConsoleHostProcess, // retrieves the pid for the process' corresponding conhost process
	ProcessWindowInformation, // returns the windowflags and windowtitle members of the process' peb->rtl_user_process_params
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

/*+0x000 InLoadOrderLinks : _LIST_ENTRY
+0x008 InMemoryOrderLinks : _LIST_ENTRY
+0x010 InInitializationOrderLinks : _LIST_ENTRY
+0x018 DllBase          : Ptr32 Void
+0x01c EntryPoint       : Ptr32 Void
+0x020 SizeOfImage      : Uint4B
+0x024 FullDllName      : _UNICODE_STRING
+0x02c BaseDllName      : _UNICODE_STRING
+0x034 Flags            : Uint4B
+0x038 LoadCount        : Uint2B
+0x03a TlsIndex         : Uint2B
+0x03c HashLinks        : _LIST_ENTRY
+0x03c SectionPointer   : Ptr32 Void
+0x040 CheckSum         : Uint4B
+0x044 TimeDateStamp    : Uint4B
+0x044 LoadedImports    : Ptr32 Void
+0x048 EntryPointActivationContext : Ptr32 Void
+0x04c PatchInformation : Ptr32 Void*/
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	DWORD  DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;

	union{
		LIST_ENTRY HashLinks;
		DWORD SectionPointer;
	};

	DWORD CheckSum;

	union{
		DWORD TimeDateStamp;
		DWORD LoadedImports;
	};

	DWORD EntryPointActivationContext;
	DWORD PatchInformation; 
	
} LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(CALLBACK *NTQUERYINFORMATIONPROCESS)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS processInfo,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength OPTIONAL
	);

//DLLMain��������
typedef BOOL (WINAPI *lpFuncDLLMain)(HINSTANCE,DWORD,LPVOID);
lpFuncDLLMain pDLLMain = NULL;//DLLMain����ָ��

char* lpMemBuf;//DLL�ڴ滺����
DWORD dwMemBufSize;//DLL�ڴ滺������С

//PE�ļ��ṹ��ָ���������
IMAGE_DOS_HEADER *lpFileDOSHeader,*lpMemDOSHeader;//DOSͷ
IMAGE_NT_HEADERS *lpFileNTHeader,*lpMemNTHeader;//NTͷ
IMAGE_SECTION_HEADER *lpFileSectionHeader,*lpMemSectionHeader;//��ͷ
IMAGE_IMPORT_DESCRIPTOR *lpMemImportDescriptor;//�����
IMAGE_BASE_RELOCATION *lpMemRelocationDescriptor;//�ض����
IMAGE_EXPORT_DIRECTORY *lpMemExportDescriptor;//������
//PEB��LDR��ָ�Ľṹ��ָ�����
LDR_DATA_TABLE_ENTRY *lpMemLDRDataTableEntry;


bool IsDebugged()
{
	char result = 0;
	__asm
	{
		// ���̵�PEB��ַ
		mov eax, fs:[30h]
		// ��ѯBeingDebugged��־λ
		mov al, BYTE PTR[eax + 2]
		mov result, al
	}

	return result != 0;
}

//�����ڵ���״̬ʱ������ϵͳ�����޸�BeingDebugged�����־λ���⣬�����޸����������ط�������NtDll��һЩ���ƶѣ�Heap�������ĺ����ı�־λ�ͻᱻ�޸ģ����Ҳ���Բ�ѯ�����־λ��
bool PebNtGlobalFlags()
{
	int result = 0;

	__asm
	{
		// ���̵�PEB
		mov eax, fs:[30h]
		// ���ƶѲ��������Ĺ�����ʽ�ı�־λ NtGlobalFlag
		mov eax, [eax + 68h]
		// ����ϵͳ�������Щ��־λFLG_HEAP_ENABLE_TAIL_CHECK, 
		// FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS��
		// ���ǵĲ�������x70
		and eax, 0x70
		mov result, eax
	}

	return result != 0;
}

bool HeapFlag()
{
	int result = 0;
	__asm
	{
		
		mov     eax, fs:[0x30]
		mov		eax, DWORD ptr[eax + 0x18] // PEB.ProcessHeap
		mov		eax, DWORD ptr[eax + 0x0c] // heap flag
		mov		result, eax
	}
	// heapflag�����������2
	return result != 2;
}

//�����ڶ��Ϸ�����ڴ棬�ڷ���Ķѵ�ͷ��Ϣ�ForceFlags�����־λ�ᱻ�޸ģ���˿���ͨ���ж������־λ�ķ�ʽ��������
bool ForceFlag()
{
	int result = 0;

	__asm
	{
		// ���̵�PEB
		mov eax, fs:[30h]
		// ���̵Ķѣ���������һ���ѣ�������Ĭ�ϵĶ�
		mov eax, [eax + 18h]
		// ���ForceFlag��־λ����û�б����Ե������Ӧ����0
		mov eax, [eax + 10h]
		mov result, eax
	}

	return result != 0;
}

//���Զ˿�
bool DebugPort()
{

	bool bRet = FALSE;
	HMODULE hNtdll = NULL;
	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;
	DWORD dwDebugPort = 0;

	hNtdll = LoadLibraryW(L"ntdll.dll");
	if (NULL != hNtdll)
	{
		pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		if (NULL != pNtQueryInformationProcess)
		{
			pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, sizeof(dwDebugPort), NULL);
		}

		dwDebugPort == -1 ? bRet = TRUE : bRet = FALSE;
		pNtQueryInformationProcess = NULL;
		FreeLibrary(hNtdll);
	}
	return bRet;
}

//���ļ�,��ȡ�ļ�����,�����VirtualAlloc�ͷ��ڴ�
BYTE* PeOpenFile(char* FileName, DWORD* dwZipFileSize)
{
	DWORD dwResult = 0;
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LOG("%s�ļ���ʧ��%d\n", FileName, ERRORCODE);
		return NULL;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);//��ȡDLL�ļ���С
	if (FileSize == 0xFFFFFFFFF)
	{
		LOG("%s��ȡ�ļ���Сʧ��%d\n", FileName, ERRORCODE);
		return NULL;
	}
	//��ȡѹ�����ļ���С
	*dwZipFileSize = FileSize - 4;
	LOG("ѹ���ļ���С:%d\n", *dwZipFileSize);
	BYTE* lpZipBuf = new BYTE[FileSize];
	if (lpZipBuf == NULL)
	{
		return NULL;
	}
	DWORD dwReadSize = 0;
	dwResult = ReadFile(hFile, lpZipBuf, FileSize, &dwReadSize, NULL);//����DLL�ļ�
	if (dwResult == 0 || FileSize != dwReadSize)
	{
		LOG("�ļ���ȡʧ��:%d\n", ERRORCODE);
		return NULL;
	}
	CloseHandle(hFile);

	return lpZipBuf;
}

//���ļ����н�ѹ��
bool unZip(BYTE* lpUnZipBuf, DWORD* dwSrcFileSize, BYTE* lpZipBuf, DWORD dwZipFileSize)
{
	DWORD dwResult = 0;
	if (lpZipBuf == NULL)
	{
		return false;
	}
	
	ZLibSDk zSdk;
	if (zSdk.LoadDllStatus() != 0)
	{
		return false;
	}
	
	dwResult = zSdk.uncompress(lpUnZipBuf, dwSrcFileSize, lpZipBuf + 4, dwZipFileSize);
	if (dwResult != Z_OK)
	{
		LOG("uncompress : %d\n", dwResult);
		return false;
	}

	return true;
}

//AES key
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

//�ļ�������У��
bool isModify(char* lpFileBuf)
{	
	LOG("1111111111111111111\n");
	IMAGE_DOS_HEADER* lpIDHeader = (IMAGE_DOS_HEADER*)lpFileBuf;
	char* FileBuf = lpFileBuf + lpIDHeader->e_lfanew; 
	//NTͷУ��
	DWORD dwNewCRC = CRC32((unsigned char*)FileBuf, sizeof(IMAGE_NT_HEADERS));
	DllInfo *lpPEInfo = (DllInfo*)(lpFileBuf + sizeof(IMAGE_DOS_HEADER));
	DWORD dwOldCRC = lpPEInfo->dwCRC32;
	if(dwNewCRC == dwOldCRC)
	{
		LOG("�ļ�������У��ͨ��, Old: %0x, New: %0x\n", dwOldCRC, dwNewCRC);
		return true;
	}		
	else
	{
		return false;	
	}		
}

//������У��ͨ��
bool isSameMachineCode(char* lpFileBuf)
{
	IMAGE_DOS_HEADER* lpIDHeader = (IMAGE_DOS_HEADER*)lpFileBuf;
	char* FileBuf = lpFileBuf + lpIDHeader->e_lfanew;
	DllInfo *lpPEInfo = (DllInfo*)(lpFileBuf + sizeof(IMAGE_DOS_HEADER));
	char szOldAESkey[16] = "";
	strncpy(szOldAESkey, lpPEInfo->szAESKey, sizeof(szOldAESkey));
	char szNewAESKey[16] = "";
	sprintf_s(szNewAESKey, "%0x", GetCPUID());
	if (0 == strcmp(szOldAESkey, szNewAESKey))
	{
		LOG("������У��ͨ��, szOldAESkey: %s, szNewAESkey: %s\n", szOldAESkey, szNewAESKey);
		return true;
	}
	else
	{
		return false;
	}
}

void LoadPEHeader(char* FileBuf)//����PEͷ
{
	lpFileDOSHeader = (PIMAGE_DOS_HEADER)FileBuf;//��ȡDOSͷ��ַ
	lpFileNTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuf + lpFileDOSHeader -> e_lfanew);//��ȡNTͷ��ַ
	lpFileSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileNTHeader + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + lpFileNTHeader->FileHeader.SizeOfOptionalHeader);//��ȡ��ͷ��ַ
	dwMemBufSize = lpFileNTHeader -> OptionalHeader.SizeOfImage;//��ȡDLL�ڴ�ӳ���С
	lpMemBuf = (char *)VirtualAlloc(NULL, dwMemBufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//����DLL�ڴ�
	lpMemDOSHeader = (PIMAGE_DOS_HEADER)lpMemBuf;//��ȡDLL�ڴ���DOSͷ��ַ
	CopyMemory(lpMemDOSHeader, lpFileDOSHeader, lpFileNTHeader -> OptionalHeader.SizeOfHeaders);//��PEͷ���ؽ��ڴ�
	lpMemNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpMemBuf + lpMemDOSHeader -> e_lfanew);//��ȡDLL�ڴ���NTͷ��ַ
	lpMemSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpMemNTHeader + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + lpMemNTHeader -> FileHeader.SizeOfOptionalHeader);//��ȡDLL�ڴ��н�ͷ��ַ
}

void LoadSectionData(char* FileBuf)//���ؽ�����
{
	int i = 0;

	for( ; i < lpMemNTHeader -> FileHeader.NumberOfSections; ++i)//���ļ��г��Ȳ�Ϊ0�Ľ��е����ݿ�����DLL�ڴ���
	{
		if(lpMemSectionHeader[i].SizeOfRawData > 0)
		{
			CopyMemory((LPVOID)((DWORD)lpMemBuf + lpMemSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)FileBuf + ((lpFileSectionHeader[i].PointerToRawData % lpFileNTHeader -> OptionalHeader.FileAlignment == 0) ? lpFileSectionHeader[i].PointerToRawData : 0)), lpFileSectionHeader[i].SizeOfRawData);
		}
	}
}

void RepairIAT()//�޸������
{
	int i;
	PIMAGE_THUNK_DATA32 INT;//INT��ַ
	LPDWORD IAT;//IAT��ַ
	HMODULE hMod;//DLL���
	LPCSTR LibraryName;//������
	PIMAGE_IMPORT_BY_NAME IIN;//�������ƽṹ��
	LPVOID FuncAddress;//������ַ

	lpMemImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);//��ȡDLL�ڴ��е�����������ַ
	DWORD Mem_Import_Descriptorn = lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);//��ȡ��������������

	for(i = 0;i < Mem_Import_Descriptorn; ++i)//��������������
	{
		INT = (PIMAGE_THUNK_DATA32)((DWORD)lpMemBuf + lpMemImportDescriptor[i].OriginalFirstThunk);//��ȡDLL�ڴ���INT��ַ
		IAT = (LPDWORD)((DWORD)lpMemBuf + lpMemImportDescriptor[i].FirstThunk);//��ȡDLL�ڴ���IAT��ַ

		if(lpMemImportDescriptor[i].OriginalFirstThunk == NULL)//��INT��ַΪNULL������ΪINT�ĵ�ַ��IAT�ĵ�ַ���
		{
			INT = (PIMAGE_THUNK_DATA32)IAT;
		}

		if(lpMemImportDescriptor[i].FirstThunk != NULL)//��IAT�ĵ�ַ��ΪNULL������Ч������
		{
			LibraryName = (LPCSTR)((DWORD)lpMemBuf + lpMemImportDescriptor[i].Name);//��ȡ���ļ���
			hMod = GetModuleHandleA(LibraryName);//��ȡ����

			if(hMod == NULL)//����δ�����أ�����ؿ�
			{
				hMod = LoadLibraryA(LibraryName);
			}

			while(INT -> u1.AddressOfData != NULL)//����INT��ֱ������NULL��
			{
				if((INT -> u1.AddressOfData & 0x80000000) == NULL)//��Ҫʹ�����ƻ�ȡ������ַ
				{
					IIN = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpMemBuf + INT -> u1.AddressOfData);//��ȡ�������ƽṹ��
					FuncAddress = GetProcAddress(hMod, (LPCSTR)IIN->Name);
				}
				else//��Ҫʹ����Ż�ȡ������ַ
				{
					FuncAddress = GetProcAddress(hMod,(LPCSTR)(INT -> u1.Ordinal & 0x000000FF));
				}

				*IAT = (DWORD)FuncAddress;//��������ĺ�����ַд��IAT

				//��INT��IATָ����һ��
				INT = (PIMAGE_THUNK_DATA32)((DWORD)INT + sizeof(IMAGE_THUNK_DATA32));
				IAT = (LPDWORD)((DWORD)IAT + sizeof(DWORD));
			}
		}
	}
}

void* FUNCCALLMODE GetProcAddressByOrindal(short Orindal)
{
	lpMemExportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpMemBuf + lpMemNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);//��ȡDLL�ڴ��е������ַ

	if (lpMemExportDescriptor->NumberOfFunctions == 0)
	{
		return NULL;
	}
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfFunctions);
	//ordinals - base = Y
	WORD FuncOrdinals = Orindal - lpMemExportDescriptor->Base;
	//����������ַ���ҵ��±��Ӧ�ĵ�ַ
	return (void*)((DWORD)lpMemBuf + *(AddressOfFunctions + FuncOrdinals));
}

void* FUNCCALLMODE GetProcAddressByName(char* FunName)
{
	lpMemExportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpMemBuf + lpMemNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);//��ȡDLL�ڴ��е������ַ
	//�����Ƶ������������е��������ĸ���
	if (lpMemExportDescriptor->NumberOfNames == 0 || lpMemExportDescriptor->NumberOfFunctions == 0) 
	{
		return NULL;
	}
	//��ȡ���Ʊ�,��ű�,������ַ��
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfFunctions);
	DWORD* AddressOfNames = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfNames);
	WORD* AddressOfNameOrdinals = (WORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfNameOrdinals); 
	// �����Ƶ�ַ�����ַ����Ƚ�,�ҵ�����index
	int OrdinalsIndex = 0;
	char* lpFuncNameAddr = NULL;
	while (AddressOfNames != NULL)
	{
		//ָ�������Ƶĵ�ַ
		lpFuncNameAddr = (char*)((DWORD)lpMemBuf + *AddressOfNames);
		if (0 == strcmp(lpFuncNameAddr, FunName))
		{
			break;
		}
		++AddressOfNames;
		++OrdinalsIndex;
	}
	// �����������ҵ�����index�ж�Ӧ��ֵX
	DWORD FuncIndex = *(AddressOfNameOrdinals + OrdinalsIndex);
	// ����������ַ���ҵ��±�X��Ӧ�ĵ�ַ
	DWORD FuncAddrRVA = *(AddressOfFunctions + FuncIndex);

	return (void*)((DWORD)lpMemBuf + FuncAddrRVA);
}

void RepairOperateAddress()//�޸��ض����ַ
{
	int i;
	int RelocDatan;//�ض��������
	WORD Offset;//�ض���ƫ��
	BYTE Type;//�ض�������
	DWORD AddValue;//��ǰImageBase��ԭImageBase��ֵ
	DWORD BaseAddress;//�ض����Ļ�ַ
	LPDWORD lpDest;//ָ����Ҫ�ض����ַ�ĵط�
	LPWORD lpRelocData;//��ǰ�ض�����ض�������ַ
	
	lpMemRelocationDescriptor = (PIMAGE_BASE_RELOCATION)((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	while((DWORD)lpMemRelocationDescriptor < ((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
	{
		lpRelocData = (LPWORD)((DWORD)lpMemRelocationDescriptor + sizeof(IMAGE_BASE_RELOCATION));//��ȡ��ǰ�ض�����ض�������ַ
		RelocDatan = (lpMemRelocationDescriptor->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);//��ȡ�ض��������
		AddValue = (DWORD)lpMemBuf - lpMemNTHeader -> OptionalHeader.ImageBase;//��ȡ��ǰImageBase��ԭImageBase��ֵ
		BaseAddress = (DWORD)lpMemBuf + lpMemRelocationDescriptor -> VirtualAddress;//��ȡ�ض����Ļ�ַ
		
		for (i = 0; i < RelocDatan; i++)//�����ض������
		{
			Offset = lpRelocData[i] & 0x0FFF;//��ȡ�ض���ƫ��
			Type = (BYTE)(lpRelocData[i] >> 12);//��ȡ�ض�������
			lpDest = (DWORD *)(BaseAddress + Offset);//��ȡ��Ҫ�ض����ַ�ĵط�

			//��ַ�ض���
			switch (Type)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				case IMAGE_REL_BASED_HIGH:		
					*lpDest = (((AddValue & 0xFFFF0000) + ((*lpDest) & 0xFFFF0000)) & 0xFFFF0000) | ((*lpDest) & 0x0000FFFF);
					break;

				case IMAGE_REL_BASED_LOW:
					*lpDest += (((AddValue & 0x0000FFFF) + ((*lpDest) & 0x0000FFFF)) & 0x0000FFFF) | ((*lpDest) & 0xFFFF0000);
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*lpDest += AddValue;
					break;

				case IMAGE_REL_BASED_HIGHADJ:
					*lpDest = (((AddValue & 0xFFFF0000) + ((*lpDest) & 0xFFFF0000)) & 0xFFFF0000) | ((*lpDest) & 0x0000FFFF);
					break;

				default:
					break;
			}
		}

		lpMemRelocationDescriptor = (PIMAGE_BASE_RELOCATION)((DWORD)lpMemRelocationDescriptor + lpMemRelocationDescriptor -> SizeOfBlock);//ָ����һ���ض����
	}
}

void AddDLLToPEB(char* DLLName)//��DLL��Ϣ����PEB��LDR��
{
	PPEB PEB;//PEB��ַ
	PPEB_LDR_DATA LDR;//LDR��ַ
	PLDR_DATA_TABLE_ENTRY EndModule;//����ģ���ַ
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//����PEB��ַ
	
	PEB = (PPEB)(*PEBAddress);//��ȡPEB��ַ
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//��ȡLDR��ַ

	//����LDR.InLoadOrderModuleList�Ի�ý���ģ���ַ
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	lpMemLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)VirtualAlloc(NULL,sizeof(LDR_DATA_TABLE_ENTRY),MEM_COMMIT,PAGE_READWRITE);//����LDR���ݱ��ڴ�

	//��DLL����InLoadOrderModuleList
	EndModule -> InLoadOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;
	lpMemLDRDataTableEntry -> InLoadOrderLinks.Flink = &EndModule -> InLoadOrderLinks;
	lpMemLDRDataTableEntry -> InLoadOrderLinks.Blink = EndModule -> InLoadOrderLinks.Blink;
	EndModule -> InLoadOrderLinks.Blink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;
	LDR -> InLoadOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;

	//��DLL����InMemoryOrderModuleList
	EndModule -> InMemoryOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;
	lpMemLDRDataTableEntry -> InMemoryOrderLinks.Flink = &EndModule -> InMemoryOrderLinks;
	lpMemLDRDataTableEntry -> InMemoryOrderLinks.Blink = EndModule -> InMemoryOrderLinks.Blink;
	EndModule -> InMemoryOrderLinks.Blink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;
	LDR -> InMemoryOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;

	//��DLL����InInitializationOrderModuleList
	EndModule -> InInitializationOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;
	lpMemLDRDataTableEntry -> InInitializationOrderLinks.Flink = &EndModule -> InInitializationOrderLinks;
	lpMemLDRDataTableEntry -> InInitializationOrderLinks.Blink = EndModule -> InInitializationOrderLinks.Blink;
	EndModule -> InInitializationOrderLinks.Blink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;
	LDR -> InInitializationOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;

	lpMemLDRDataTableEntry -> DllBase = (DWORD)lpMemBuf;//д��DLL�ڴ��ַ
	lpMemLDRDataTableEntry -> EntryPoint = (DWORD)(lpMemNTHeader -> OptionalHeader.AddressOfEntryPoint + (DWORD)lpMemBuf);//д��DLL��ڵ��ַ
	lpMemLDRDataTableEntry -> SizeOfImage = dwMemBufSize;//д��DLLģ���С

	int  unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, DLLName, -1, NULL, 0);
	wchar_t *  Mem_DLLName;
	Mem_DLLName = new  wchar_t[unicodeLen + 1];
	memset(Mem_DLLName, 0, (unicodeLen + 1) * sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP, 0, DLLName, -1, (LPWSTR)Mem_DLLName, unicodeLen);

	//д��DLL������
	lpMemLDRDataTableEntry->BaseDllName.Buffer = (PWSTR)VirtualAlloc(NULL, wcslen(Mem_DLLName) * sizeof(WCHAR) + 2, MEM_COMMIT, PAGE_READWRITE);
	lpMemLDRDataTableEntry->BaseDllName.Length = wcslen(Mem_DLLName) * sizeof(WCHAR);
	lpMemLDRDataTableEntry -> BaseDllName.MaximumLength = lpMemLDRDataTableEntry -> BaseDllName.Length;
	CopyMemory((LPVOID)lpMemLDRDataTableEntry->BaseDllName.Buffer, (LPVOID)Mem_DLLName, lpMemLDRDataTableEntry->BaseDllName.Length + 2);

	//д��DLLȫ��
	lpMemLDRDataTableEntry->FullDllName.Buffer = (PWSTR)VirtualAlloc(NULL, wcslen(Mem_DLLName) * sizeof(WCHAR)+2, MEM_COMMIT, PAGE_READWRITE);
	lpMemLDRDataTableEntry->FullDllName.Length = wcslen(Mem_DLLName) * sizeof(WCHAR);
	lpMemLDRDataTableEntry -> FullDllName.MaximumLength = lpMemLDRDataTableEntry -> FullDllName.Length;
	CopyMemory((LPVOID)lpMemLDRDataTableEntry->FullDllName.Buffer, (LPVOID)Mem_DLLName, lpMemLDRDataTableEntry->FullDllName.Length + 2);
	
	delete Mem_DLLName;
	Mem_DLLName = NULL;

	lpMemLDRDataTableEntry -> LoadCount = 1;//��DLL���ش�����1
}

void DLLInit()//DLL��ʼ��
{
	pDLLMain = (lpFuncDLLMain)(lpMemNTHeader -> OptionalHeader.AddressOfEntryPoint + (DWORD)lpMemBuf);//DLL��ڵ㼴��ȡDLLMain������ַ
	pDLLMain((HINSTANCE)lpMemBuf, DLL_PROCESS_ATTACH, NULL);//ִ��DLLMain
}

//DLLNameΪ���ܺ��DLL������
char* FUNCCALLMODE DLLMemLoad(char* DLLName)
{
#ifdef CHECK_DEBUG
	if (IsDebugged() || PebNtGlobalFlags() || HeapFlag() || DebugPort())
	{
		LOG("has Debugger\n");
		return NULL;
	}
#endif
	bool ret = false;
	BYTE* lpZipBuf = NULL; 
	BYTE* lpUnZipBuf = NULL;
	char szAesKey[16] = "";
	DWORD dwZipFileSize = 0;
	//��ȡѹ�����DLL
	lpZipBuf = PeOpenFile(DLLName, &dwZipFileSize);
	if (lpZipBuf == NULL)
	{
		LOG("PeOpenFile fail\n");
		lpMemBuf = NULL;
	}
	//��ȡ�ļ���С,��ѹ��
	DWORD dwSrcFileSize = *(DWORD*)lpZipBuf;
	lpUnZipBuf = new BYTE[dwSrcFileSize];
	if (lpUnZipBuf == NULL)
	{
		LOG("malloc fail\n");
		return false;
	}
	memset(lpUnZipBuf, 0, sizeof(lpUnZipBuf));
	ret = unZip(lpUnZipBuf, &dwSrcFileSize, lpZipBuf, dwZipFileSize);
	if (ret == false)
	{
		LOG("uncompress fail\n");
		lpMemBuf = NULL;
	}
	LOG("unCompress OK, %d\n", dwSrcFileSize);
	//����
	BYTE* lpFileBuf = new BYTE[dwSrcFileSize];
	if (lpFileBuf == NULL)
	{
		lpMemBuf = NULL;
	}
	memset(lpFileBuf, 0, sizeof(lpFileBuf));
	sprintf_s(szAesKey, "%0x", GetCPUID());
	
	Botan::SecureVector<Botan::byte> vector_in(lpUnZipBuf, dwSrcFileSize);
	Botan::SecureVector<Botan::byte> vector_out(lpFileBuf, dwSrcFileSize);
	CryptoAES128(vector_in, szAesKey, Botan::Cipher_Dir::DECRYPTION, vector_out); 

	if (isModify((char*)vector_out.data()) && isSameMachineCode((char*)vector_out.data()))
	{
		LoadPEHeader((char*)vector_out.data());
		LoadSectionData((char*)vector_out.data());
		RepairIAT();
		RepairOperateAddress();
		AddDLLToPEB(DLLName);
		DLLInit();
	}

	if (lpZipBuf == NULL)
	{
		delete[] lpZipBuf;
		lpZipBuf = NULL;
	}
	if (lpUnZipBuf == NULL)
	{
		delete[] lpUnZipBuf;
		lpUnZipBuf = NULL;
	}
	if (lpFileBuf == NULL)
	{
		delete[] lpFileBuf;
		lpFileBuf = NULL;
	}

	return lpMemBuf;//����DLL�ڴ��ַ��DLL���
}

void FUNCCALLMODE DLLMemFree(char* DLLMemBaseAddress)//DLL�ڴ��ͷź��������ڳ������֮ǰ�������ͷż��ص�DLL�����������ܻ��쳣�˳�
{
	PPEB PEB;//PEB��ַ
	PPEB_LDR_DATA LDR;//LDR��ַ
	PLDR_DATA_TABLE_ENTRY CurModule;//��ǰģ���ַ
	PLDR_DATA_TABLE_ENTRY EndModule;//����ģ���ַ
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//����PEB��ַ

	lpMemBuf = DLLMemBaseAddress;//��ʼ��lpMemBufָ�����

	PEB = (PPEB)(*PEBAddress);//��ȡPEB��ַ
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//��ȡLDR��ַ

	//����LDR.InLoadOrderModuleList�Ի��DLLģ���ַ
	CurModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(CurModule -> DllBase != NULL)
	{
		if(CurModule -> DllBase == (DWORD)DLLMemBaseAddress)
		{
			break;
		}

		CurModule = (PLDR_DATA_TABLE_ENTRY) CurModule -> InLoadOrderLinks.Flink;
	}

	if(CurModule -> DllBase == NULL)//��DLLģ��δ�ҵ�
	{
		return;
	}

	//����LDR.InLoadOrderModuleList�Ի�ý���ģ���ַ
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	//��DLL��InLoadOrderModuleList��ж��
	CurModule -> InLoadOrderLinks.Flink -> Blink = CurModule -> InLoadOrderLinks.Blink;
	CurModule -> InLoadOrderLinks.Blink -> Flink = CurModule -> InLoadOrderLinks.Flink;

	//��DLL��InMemoryOrderModuleList��ж��
	CurModule -> InMemoryOrderLinks.Flink -> Blink = CurModule -> InMemoryOrderLinks.Blink;
	CurModule -> InMemoryOrderLinks.Blink -> Flink = CurModule -> InMemoryOrderLinks.Flink;

	//��DLL��InInitializationOrderModuleList��ж��
	CurModule -> InInitializationOrderLinks.Flink -> Blink = CurModule -> InInitializationOrderLinks.Blink;
	CurModule -> InInitializationOrderLinks.Blink -> Flink = CurModule -> InInitializationOrderLinks.Flink;

	//�޸�LDR���������Blink
	LDR -> InLoadOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InMemoryOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InInitializationOrderModuleList.Blink = EndModule -> InInitializationOrderLinks.Blink;

	dwMemBufSize = lpMemLDRDataTableEntry -> SizeOfImage;//��ʼ��dwMemBufSize����
	VirtualFree((LPVOID)lpMemBuf,dwMemBufSize,MEM_DECOMMIT);//�ͷ�DLL�ڴ�

	//�ͷ�DLLģ�������ṹ����ռ�ڴ�ռ�
	VirtualFree((LPVOID)CurModule -> BaseDllName.Buffer,CurModule -> BaseDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule -> FullDllName.Buffer,CurModule -> FullDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule,sizeof(LDR_DATA_TABLE_ENTRY),MEM_DECOMMIT);
}