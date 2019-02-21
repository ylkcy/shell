#include "DLLLoader.h"
#include "log.h"
#include "AES.h"
#include "ZlibSdk.h"
#include "CheckSum.h"


typedef struct DllInfo
{
	DWORD dwCRC32; //用于校验文件的完整性, 计算IMAGE_DOS_HEADER的大小
	char  szAESKey[16]; //AES key
}DllInfo;

typedef struct _PEB 
{ // Size: 0x1D8  
	/*000*/ UCHAR InheritedAddressSpace;  
	/*001*/ UCHAR ReadImageFileExecOptions;  
	/*002*/ UCHAR BeingDebugged;  //IsDebuggerPresent() 进程是否处于调试状态
	/*003*/ UCHAR SpareBool;  
	/*004*/ HANDLE Mutant;  
	/*008*/ DWORD ImageBaseAddress; // ImageBase 
	/*00C*/ DWORD DllList;          //当DLL加载到进程，可从 PEB.Ldr中获取该模块的基址和其他信息  
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

//DLLMain函数声明
typedef BOOL (WINAPI *lpFuncDLLMain)(HINSTANCE,DWORD,LPVOID);
lpFuncDLLMain pDLLMain = NULL;//DLLMain函数指针

char* lpMemBuf;//DLL内存缓冲区
DWORD dwMemBufSize;//DLL内存缓冲区大小

//PE文件结构体指针变量声明
IMAGE_DOS_HEADER *lpFileDOSHeader,*lpMemDOSHeader;//DOS头
IMAGE_NT_HEADERS *lpFileNTHeader,*lpMemNTHeader;//NT头
IMAGE_SECTION_HEADER *lpFileSectionHeader,*lpMemSectionHeader;//节头
IMAGE_IMPORT_DESCRIPTOR *lpMemImportDescriptor;//导入表
IMAGE_BASE_RELOCATION *lpMemRelocationDescriptor;//重定向表
IMAGE_EXPORT_DIRECTORY *lpMemExportDescriptor;//导出表
//PEB中LDR所指的结构体指针变量
LDR_DATA_TABLE_ENTRY *lpMemLDRDataTableEntry;


bool IsDebugged()
{
	char result = 0;
	__asm
	{
		// 进程的PEB地址
		mov eax, fs:[30h]
		// 查询BeingDebugged标志位
		mov al, BYTE PTR[eax + 2]
		mov result, al
	}

	return result != 0;
}

//当处于调试状态时，操作系统除了修改BeingDebugged这个标志位以外，还会修改其他几个地方，其中NtDll中一些控制堆（Heap）操作的函数的标志位就会被修改，因此也可以查询这个标志位，
bool PebNtGlobalFlags()
{
	int result = 0;

	__asm
	{
		// 进程的PEB
		mov eax, fs:[30h]
		// 控制堆操作函数的工作方式的标志位 NtGlobalFlag
		mov eax, [eax + 68h]
		// 操作系统会加上这些标志位FLG_HEAP_ENABLE_TAIL_CHECK, 
		// FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS，
		// 它们的并集就是x70
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
	// heapflag正常情况下是2
	return result != 2;
}

//进程在堆上分配的内存，在分配的堆的头信息里，ForceFlags这个标志位会被修改，因此可以通过判断这个标志位的方式来反调试
bool ForceFlag()
{
	int result = 0;

	__asm
	{
		// 进程的PEB
		mov eax, fs:[30h]
		// 进程的堆，随便访问了一个堆，下面是默认的堆
		mov eax, [eax + 18h]
		// 检查ForceFlag标志位，在没有被调试的情况下应该是0
		mov eax, [eax + 10h]
		mov result, eax
	}

	return result != 0;
}

//调试端口
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

//打开文件,读取文件内容,需调用VirtualAlloc释放内存
BYTE* PeOpenFile(char* FileName, DWORD* dwZipFileSize)
{
	DWORD dwResult = 0;
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LOG("%s文件打开失败%d\n", FileName, ERRORCODE);
		return NULL;
	}
	DWORD FileSize = GetFileSize(hFile, NULL);//获取DLL文件大小
	if (FileSize == 0xFFFFFFFFF)
	{
		LOG("%s获取文件大小失败%d\n", FileName, ERRORCODE);
		return NULL;
	}
	//获取压缩后文件大小
	*dwZipFileSize = FileSize - 4;
	LOG("压缩文件大小:%d\n", *dwZipFileSize);
	BYTE* lpZipBuf = new BYTE[FileSize];
	if (lpZipBuf == NULL)
	{
		return NULL;
	}
	DWORD dwReadSize = 0;
	dwResult = ReadFile(hFile, lpZipBuf, FileSize, &dwReadSize, NULL);//读入DLL文件
	if (dwResult == 0 || FileSize != dwReadSize)
	{
		LOG("文件读取失败:%d\n", ERRORCODE);
		return NULL;
	}
	CloseHandle(hFile);

	return lpZipBuf;
}

//对文件进行解压缩
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

//文件完整性校验
bool isModify(char* lpFileBuf)
{	
	LOG("1111111111111111111\n");
	IMAGE_DOS_HEADER* lpIDHeader = (IMAGE_DOS_HEADER*)lpFileBuf;
	char* FileBuf = lpFileBuf + lpIDHeader->e_lfanew; 
	//NT头校验
	DWORD dwNewCRC = CRC32((unsigned char*)FileBuf, sizeof(IMAGE_NT_HEADERS));
	DllInfo *lpPEInfo = (DllInfo*)(lpFileBuf + sizeof(IMAGE_DOS_HEADER));
	DWORD dwOldCRC = lpPEInfo->dwCRC32;
	if(dwNewCRC == dwOldCRC)
	{
		LOG("文件完整性校验通过, Old: %0x, New: %0x\n", dwOldCRC, dwNewCRC);
		return true;
	}		
	else
	{
		return false;	
	}		
}

//机器码校验通过
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
		LOG("机器码校验通过, szOldAESkey: %s, szNewAESkey: %s\n", szOldAESkey, szNewAESKey);
		return true;
	}
	else
	{
		return false;
	}
}

void LoadPEHeader(char* FileBuf)//加载PE头
{
	lpFileDOSHeader = (PIMAGE_DOS_HEADER)FileBuf;//获取DOS头地址
	lpFileNTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuf + lpFileDOSHeader -> e_lfanew);//获取NT头地址
	lpFileSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileNTHeader + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + lpFileNTHeader->FileHeader.SizeOfOptionalHeader);//获取节头基址
	dwMemBufSize = lpFileNTHeader -> OptionalHeader.SizeOfImage;//获取DLL内存映像大小
	lpMemBuf = (char *)VirtualAlloc(NULL, dwMemBufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//分配DLL内存
	lpMemDOSHeader = (PIMAGE_DOS_HEADER)lpMemBuf;//获取DLL内存中DOS头地址
	CopyMemory(lpMemDOSHeader, lpFileDOSHeader, lpFileNTHeader -> OptionalHeader.SizeOfHeaders);//将PE头加载进内存
	lpMemNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpMemBuf + lpMemDOSHeader -> e_lfanew);//获取DLL内存中NT头地址
	lpMemSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpMemNTHeader + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER32) + lpMemNTHeader -> FileHeader.SizeOfOptionalHeader);//获取DLL内存中节头基址
}

void LoadSectionData(char* FileBuf)//加载节数据
{
	int i = 0;

	for( ; i < lpMemNTHeader -> FileHeader.NumberOfSections; ++i)//将文件中长度不为0的节中的数据拷贝到DLL内存中
	{
		if(lpMemSectionHeader[i].SizeOfRawData > 0)
		{
			CopyMemory((LPVOID)((DWORD)lpMemBuf + lpMemSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)FileBuf + ((lpFileSectionHeader[i].PointerToRawData % lpFileNTHeader -> OptionalHeader.FileAlignment == 0) ? lpFileSectionHeader[i].PointerToRawData : 0)), lpFileSectionHeader[i].SizeOfRawData);
		}
	}
}

void RepairIAT()//修复导入表
{
	int i;
	PIMAGE_THUNK_DATA32 INT;//INT基址
	LPDWORD IAT;//IAT基址
	HMODULE hMod;//DLL句柄
	LPCSTR LibraryName;//库名称
	PIMAGE_IMPORT_BY_NAME IIN;//函数名称结构体
	LPVOID FuncAddress;//函数地址

	lpMemImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);//获取DLL内存中导入描述符基址
	DWORD Mem_Import_Descriptorn = lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);//获取导入描述符数量

	for(i = 0;i < Mem_Import_Descriptorn; ++i)//遍历导入描述符
	{
		INT = (PIMAGE_THUNK_DATA32)((DWORD)lpMemBuf + lpMemImportDescriptor[i].OriginalFirstThunk);//获取DLL内存中INT地址
		IAT = (LPDWORD)((DWORD)lpMemBuf + lpMemImportDescriptor[i].FirstThunk);//获取DLL内存中IAT地址

		if(lpMemImportDescriptor[i].OriginalFirstThunk == NULL)//若INT地址为NULL，则认为INT的地址和IAT的地址相等
		{
			INT = (PIMAGE_THUNK_DATA32)IAT;
		}

		if(lpMemImportDescriptor[i].FirstThunk != NULL)//若IAT的地址不为NULL，即有效描述符
		{
			LibraryName = (LPCSTR)((DWORD)lpMemBuf + lpMemImportDescriptor[i].Name);//获取库文件名
			hMod = GetModuleHandleA(LibraryName);//获取库句柄

			if(hMod == NULL)//若库未被加载，则加载库
			{
				hMod = LoadLibraryA(LibraryName);
			}

			while(INT -> u1.AddressOfData != NULL)//遍历INT，直到遇到NULL项
			{
				if((INT -> u1.AddressOfData & 0x80000000) == NULL)//需要使用名称获取函数地址
				{
					IIN = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpMemBuf + INT -> u1.AddressOfData);//获取函数名称结构体
					FuncAddress = GetProcAddress(hMod, (LPCSTR)IIN->Name);
				}
				else//需要使用序号获取函数地址
				{
					FuncAddress = GetProcAddress(hMod,(LPCSTR)(INT -> u1.Ordinal & 0x000000FF));
				}

				*IAT = (DWORD)FuncAddress;//将更正后的函数地址写入IAT

				//让INT和IAT指向下一项
				INT = (PIMAGE_THUNK_DATA32)((DWORD)INT + sizeof(IMAGE_THUNK_DATA32));
				IAT = (LPDWORD)((DWORD)IAT + sizeof(DWORD));
			}
		}
	}
}

void* FUNCCALLMODE GetProcAddressByOrindal(short Orindal)
{
	lpMemExportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpMemBuf + lpMemNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);//获取DLL内存中导出表基址

	if (lpMemExportDescriptor->NumberOfFunctions == 0)
	{
		return NULL;
	}
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfFunctions);
	//ordinals - base = Y
	WORD FuncOrdinals = Orindal - lpMemExportDescriptor->Base;
	//遍历函数地址表找到下标对应的地址
	return (void*)((DWORD)lpMemBuf + *(AddressOfFunctions + FuncOrdinals));
}

void* FUNCCALLMODE GetProcAddressByName(char* FunName)
{
	lpMemExportDescriptor = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpMemBuf + lpMemNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);//获取DLL内存中导出表基址
	//按名称导出个数和所有导出函数的个数
	if (lpMemExportDescriptor->NumberOfNames == 0 || lpMemExportDescriptor->NumberOfFunctions == 0) 
	{
		return NULL;
	}
	//获取名称表,序号表,函数地址表
	DWORD* AddressOfFunctions = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfFunctions);
	DWORD* AddressOfNames = (DWORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfNames);
	WORD* AddressOfNameOrdinals = (WORD*)((DWORD)lpMemBuf + lpMemExportDescriptor->AddressOfNameOrdinals); 
	// 从名称地址表中字符串比较,找到索引index
	int OrdinalsIndex = 0;
	char* lpFuncNameAddr = NULL;
	while (AddressOfNames != NULL)
	{
		//指向函数名称的地址
		lpFuncNameAddr = (char*)((DWORD)lpMemBuf + *AddressOfNames);
		if (0 == strcmp(lpFuncNameAddr, FunName))
		{
			break;
		}
		++AddressOfNames;
		++OrdinalsIndex;
	}
	// 遍历索引表找到索引index中对应的值X
	DWORD FuncIndex = *(AddressOfNameOrdinals + OrdinalsIndex);
	// 遍历函数地址表找到下标X对应的地址
	DWORD FuncAddrRVA = *(AddressOfFunctions + FuncIndex);

	return (void*)((DWORD)lpMemBuf + FuncAddrRVA);
}

void RepairOperateAddress()//修复重定向地址
{
	int i;
	int RelocDatan;//重定向表项数
	WORD Offset;//重定向偏移
	BYTE Type;//重定向类型
	DWORD AddValue;//当前ImageBase与原ImageBase差值
	DWORD BaseAddress;//重定向块的基址
	LPDWORD lpDest;//指向需要重定向地址的地方
	LPWORD lpRelocData;//当前重定向块重定向表项基址
	
	lpMemRelocationDescriptor = (PIMAGE_BASE_RELOCATION)((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	while((DWORD)lpMemRelocationDescriptor < ((DWORD)lpMemBuf + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + lpMemNTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
	{
		lpRelocData = (LPWORD)((DWORD)lpMemRelocationDescriptor + sizeof(IMAGE_BASE_RELOCATION));//获取当前重定向块重定向表项基址
		RelocDatan = (lpMemRelocationDescriptor->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);//获取重定向表项数
		AddValue = (DWORD)lpMemBuf - lpMemNTHeader -> OptionalHeader.ImageBase;//获取当前ImageBase与原ImageBase差值
		BaseAddress = (DWORD)lpMemBuf + lpMemRelocationDescriptor -> VirtualAddress;//获取重定向块的基址
		
		for (i = 0; i < RelocDatan; i++)//遍历重定向表项
		{
			Offset = lpRelocData[i] & 0x0FFF;//获取重定向偏移
			Type = (BYTE)(lpRelocData[i] >> 12);//获取重定向类型
			lpDest = (DWORD *)(BaseAddress + Offset);//获取需要重定向地址的地方

			//地址重定向
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

		lpMemRelocationDescriptor = (PIMAGE_BASE_RELOCATION)((DWORD)lpMemRelocationDescriptor + lpMemRelocationDescriptor -> SizeOfBlock);//指向下一个重定向块
	}
}

void AddDLLToPEB(char* DLLName)//将DLL信息加入PEB的LDR中
{
	PPEB PEB;//PEB地址
	PPEB_LDR_DATA LDR;//LDR地址
	PLDR_DATA_TABLE_ENTRY EndModule;//结束模块地址
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//计算PEB地址
	
	PEB = (PPEB)(*PEBAddress);//获取PEB地址
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//获取LDR地址

	//遍历LDR.InLoadOrderModuleList以获得结束模块地址
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	lpMemLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)VirtualAlloc(NULL,sizeof(LDR_DATA_TABLE_ENTRY),MEM_COMMIT,PAGE_READWRITE);//分配LDR数据表内存

	//将DLL挂入InLoadOrderModuleList
	EndModule -> InLoadOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;
	lpMemLDRDataTableEntry -> InLoadOrderLinks.Flink = &EndModule -> InLoadOrderLinks;
	lpMemLDRDataTableEntry -> InLoadOrderLinks.Blink = EndModule -> InLoadOrderLinks.Blink;
	EndModule -> InLoadOrderLinks.Blink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;
	LDR -> InLoadOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InLoadOrderLinks;

	//将DLL挂入InMemoryOrderModuleList
	EndModule -> InMemoryOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;
	lpMemLDRDataTableEntry -> InMemoryOrderLinks.Flink = &EndModule -> InMemoryOrderLinks;
	lpMemLDRDataTableEntry -> InMemoryOrderLinks.Blink = EndModule -> InMemoryOrderLinks.Blink;
	EndModule -> InMemoryOrderLinks.Blink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;
	LDR -> InMemoryOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InMemoryOrderLinks;

	//将DLL挂入InInitializationOrderModuleList
	EndModule -> InInitializationOrderLinks.Blink -> Flink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;
	lpMemLDRDataTableEntry -> InInitializationOrderLinks.Flink = &EndModule -> InInitializationOrderLinks;
	lpMemLDRDataTableEntry -> InInitializationOrderLinks.Blink = EndModule -> InInitializationOrderLinks.Blink;
	EndModule -> InInitializationOrderLinks.Blink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;
	LDR -> InInitializationOrderModuleList.Blink = &lpMemLDRDataTableEntry -> InInitializationOrderLinks;

	lpMemLDRDataTableEntry -> DllBase = (DWORD)lpMemBuf;//写入DLL内存基址
	lpMemLDRDataTableEntry -> EntryPoint = (DWORD)(lpMemNTHeader -> OptionalHeader.AddressOfEntryPoint + (DWORD)lpMemBuf);//写入DLL入口点地址
	lpMemLDRDataTableEntry -> SizeOfImage = dwMemBufSize;//写入DLL模块大小

	int  unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, DLLName, -1, NULL, 0);
	wchar_t *  Mem_DLLName;
	Mem_DLLName = new  wchar_t[unicodeLen + 1];
	memset(Mem_DLLName, 0, (unicodeLen + 1) * sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP, 0, DLLName, -1, (LPWSTR)Mem_DLLName, unicodeLen);

	//写入DLL基本名
	lpMemLDRDataTableEntry->BaseDllName.Buffer = (PWSTR)VirtualAlloc(NULL, wcslen(Mem_DLLName) * sizeof(WCHAR) + 2, MEM_COMMIT, PAGE_READWRITE);
	lpMemLDRDataTableEntry->BaseDllName.Length = wcslen(Mem_DLLName) * sizeof(WCHAR);
	lpMemLDRDataTableEntry -> BaseDllName.MaximumLength = lpMemLDRDataTableEntry -> BaseDllName.Length;
	CopyMemory((LPVOID)lpMemLDRDataTableEntry->BaseDllName.Buffer, (LPVOID)Mem_DLLName, lpMemLDRDataTableEntry->BaseDllName.Length + 2);

	//写入DLL全名
	lpMemLDRDataTableEntry->FullDllName.Buffer = (PWSTR)VirtualAlloc(NULL, wcslen(Mem_DLLName) * sizeof(WCHAR)+2, MEM_COMMIT, PAGE_READWRITE);
	lpMemLDRDataTableEntry->FullDllName.Length = wcslen(Mem_DLLName) * sizeof(WCHAR);
	lpMemLDRDataTableEntry -> FullDllName.MaximumLength = lpMemLDRDataTableEntry -> FullDllName.Length;
	CopyMemory((LPVOID)lpMemLDRDataTableEntry->FullDllName.Buffer, (LPVOID)Mem_DLLName, lpMemLDRDataTableEntry->FullDllName.Length + 2);
	
	delete Mem_DLLName;
	Mem_DLLName = NULL;

	lpMemLDRDataTableEntry -> LoadCount = 1;//将DLL加载次数置1
}

void DLLInit()//DLL初始化
{
	pDLLMain = (lpFuncDLLMain)(lpMemNTHeader -> OptionalHeader.AddressOfEntryPoint + (DWORD)lpMemBuf);//DLL入口点即获取DLLMain函数地址
	pDLLMain((HINSTANCE)lpMemBuf, DLL_PROCESS_ATTACH, NULL);//执行DLLMain
}

//DLLName为加密后的DLL的名称
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
	//读取压缩后的DLL
	lpZipBuf = PeOpenFile(DLLName, &dwZipFileSize);
	if (lpZipBuf == NULL)
	{
		LOG("PeOpenFile fail\n");
		lpMemBuf = NULL;
	}
	//获取文件大小,解压缩
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
	//解密
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

	return lpMemBuf;//返回DLL内存基址即DLL句柄
}

void FUNCCALLMODE DLLMemFree(char* DLLMemBaseAddress)//DLL内存释放函数，请在程序结束之前调用它释放加载的DLL，否则程序可能会异常退出
{
	PPEB PEB;//PEB地址
	PPEB_LDR_DATA LDR;//LDR地址
	PLDR_DATA_TABLE_ENTRY CurModule;//当前模块地址
	PLDR_DATA_TABLE_ENTRY EndModule;//结束模块地址
	LPDWORD PEBAddress = (LPDWORD)((DWORD)NtCurrentTeb() + 0x00000030);//计算PEB地址

	lpMemBuf = DLLMemBaseAddress;//初始化lpMemBuf指针变量

	PEB = (PPEB)(*PEBAddress);//获取PEB地址
	LDR = (PPEB_LDR_DATA)PEB -> DllList;//获取LDR地址

	//遍历LDR.InLoadOrderModuleList以获得DLL模块地址
	CurModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(CurModule -> DllBase != NULL)
	{
		if(CurModule -> DllBase == (DWORD)DLLMemBaseAddress)
		{
			break;
		}

		CurModule = (PLDR_DATA_TABLE_ENTRY) CurModule -> InLoadOrderLinks.Flink;
	}

	if(CurModule -> DllBase == NULL)//该DLL模块未找到
	{
		return;
	}

	//遍历LDR.InLoadOrderModuleList以获得结束模块地址
	EndModule = (PLDR_DATA_TABLE_ENTRY)LDR -> InLoadOrderModuleList.Flink;

	while(EndModule -> DllBase != NULL)
	{
		EndModule = (PLDR_DATA_TABLE_ENTRY) EndModule -> InLoadOrderLinks.Flink;
	}

	//将DLL从InLoadOrderModuleList中卸载
	CurModule -> InLoadOrderLinks.Flink -> Blink = CurModule -> InLoadOrderLinks.Blink;
	CurModule -> InLoadOrderLinks.Blink -> Flink = CurModule -> InLoadOrderLinks.Flink;

	//将DLL从InMemoryOrderModuleList中卸载
	CurModule -> InMemoryOrderLinks.Flink -> Blink = CurModule -> InMemoryOrderLinks.Blink;
	CurModule -> InMemoryOrderLinks.Blink -> Flink = CurModule -> InMemoryOrderLinks.Flink;

	//将DLL从InInitializationOrderModuleList中卸载
	CurModule -> InInitializationOrderLinks.Flink -> Blink = CurModule -> InInitializationOrderLinks.Blink;
	CurModule -> InInitializationOrderLinks.Blink -> Flink = CurModule -> InInitializationOrderLinks.Flink;

	//修复LDR三个链表的Blink
	LDR -> InLoadOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InMemoryOrderModuleList.Blink = EndModule -> InLoadOrderLinks.Blink;
	LDR -> InInitializationOrderModuleList.Blink = EndModule -> InInitializationOrderLinks.Blink;

	dwMemBufSize = lpMemLDRDataTableEntry -> SizeOfImage;//初始化dwMemBufSize变量
	VirtualFree((LPVOID)lpMemBuf,dwMemBufSize,MEM_DECOMMIT);//释放DLL内存

	//释放DLL模块描述结构体所占内存空间
	VirtualFree((LPVOID)CurModule -> BaseDllName.Buffer,CurModule -> BaseDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule -> FullDllName.Buffer,CurModule -> FullDllName.Length + 2,MEM_DECOMMIT);
	VirtualFree((LPVOID)CurModule,sizeof(LDR_DATA_TABLE_ENTRY),MEM_DECOMMIT);
}