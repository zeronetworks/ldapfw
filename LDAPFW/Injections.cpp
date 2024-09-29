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
		_tprintf(TEXT("CreateToolhelp32Snapshot failed with error: [%d]\n"), GetLastError());
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

bool hookProcessLoadLibrary(DWORD processID) 
{

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, processID);
	if (hProcess == nullptr)
	{
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID, GetLastError());
		return false;
	}

	void* LLParam = (LPVOID)VirtualAllocEx(hProcess, nullptr, sizeof DLL_NAME, MEM_COMMIT, PAGE_READWRITE);
	if (LLParam == nullptr)
	{
		_tprintf(TEXT("Error when calling VirtualAllocEx %d \n"), GetLastError());
		return false;
	}

	if (WriteProcessMemory(hProcess, LLParam, DLL_NAME, sizeof DLL_NAME, NULL) == 0)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		return false;
	}

	FARPROC pLoadLib = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLib == nullptr)
	{
		_tprintf(TEXT("Error when calling GetProcAddress %d \n"), GetLastError());
		return false;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib, LLParam, 0, 0);
	if (hRemoteThread == nullptr)
	{
		_tprintf(TEXT("Error when calling CreateRemoteThread %d \n"), GetLastError());
		return false;
	}

	CloseHandle(hRemoteThread);

    return true;
}

bool isProcessProtected(const std::wstring& processName)
{
	bool isProtected = true;

	auto processId = FindProcessId(processName);
	if (processId == 0) {
		_tprintf(TEXT("Error when calling FindProcessId %d \n"), GetLastError());
		return isProtected;
	}

	HANDLE pHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

	if (pHandle != nullptr)
	{
		PROCESS_PROTECTION_LEVEL_INFORMATION ppli;
		if (GetProcessInformation(pHandle, ProcessProtectionLevelInfo, &ppli, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)))
		{
			if (ppli.ProtectionLevel == PROTECTION_LEVEL_NONE)
			{
				isProtected = false;
			}

		}
		else {
			_tprintf(TEXT("Cannot determine if LSA protection is enabled %d \n"), GetLastError());
			isProtected = false;
		}

		CloseHandle(pHandle);
	}

	return isProtected;
}