#include "stdafx.h"
#include "common.h"
#include <psapi.h>

static const char* DLL_NAME = "ldapFW";

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

bool isDllLoaded(DWORD processID, const WCHAR* dllFullPath)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	if (NULL == hProcess) {
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID, GetLastError());
		return true;
	}

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                if (_tcsicmp(szModName, dllFullPath) == 0) {
                    return true;
                }
            }
        }
    }

    CloseHandle(hProcess);

    return false;
}

void hookProcessLoadLibrary(DWORD processID) 
{

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, processID);
	if (hProcess == nullptr)
	{
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID, GetLastError());
		return;
	}

	void* LLParam = (LPVOID)VirtualAllocEx(hProcess, nullptr, sizeof DLL_NAME, MEM_COMMIT, PAGE_READWRITE);
	if (LLParam == nullptr)
	{
		_tprintf(TEXT("Error when calling VirtualAllocEx %d \n"), GetLastError());
		return;
	}

	if (WriteProcessMemory(hProcess, LLParam, DLL_NAME, sizeof DLL_NAME, NULL) == 0)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		return;
	}

	FARPROC pLoadLib = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLib == nullptr)
	{
		_tprintf(TEXT("Error when calling GetProcAddress %d \n"), GetLastError());
		return;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib, LLParam, 0, 0);
	if (hRemoteThread == nullptr)
	{
		_tprintf(TEXT("Error when calling CreateRemoteThread %d \n"), GetLastError());
		return;
	}

	CloseHandle(hRemoteThread);
}