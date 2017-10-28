#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int main()
{
	char *dll = "sweeper.dll",
		 *exe = "Winmine__XP.exe";

	/* FIND PROCESS */
	HANDLE snapshot,
		   process = 0;
	PROCESSENTRY32 pe32;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(INVALID_HANDLE_VALUE == snapshot)
		return 1;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(snapshot, &pe32))
	{
		CloseHandle(snapshot);
		return 1;
	}
	do
	{
		if(!strcmp(exe, pe32.szExeFile))
		{
			process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			break;
		}
	} while(Process32Next(snapshot, &pe32));
	CloseHandle(snapshot);

	if(!process)
	{
		printf("%s process not found\n", exe);
		return 1;
	}

	/* INJECT DLL */
	LPVOID llAddr = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	LPVOID baseAddr = (LPVOID) VirtualAllocEx(process, 0, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(!baseAddr)
	{
		printf("Memory could not be allocated\n");
		CloseHandle(process);
		return 1;
	}
	if(!WriteProcessMemory(process, baseAddr, dll, strlen(dll), 0))
	{
		printf("Memory could not be written\n");
		CloseHandle(process);
		return 1;
	}
	HANDLE thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE) llAddr, baseAddr, 0, 0);
	if(!thread)
	{
		printf("Remote thread could not be created\n");
		CloseHandle(process);
		return 1;
	}
	printf("Remote thread created\n");

	CloseHandle(process);

	return 0;
}