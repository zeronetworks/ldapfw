#include "stdafx.h"
#include "common.h"

bool interactive;
HANDLE globalMappedMemory = nullptr;
HANDLE globalUnprotectEvent = nullptr;

std::wstring StringToWString(const std::string& s)
{
	std::wstring temp(s.length(), L' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string confStr)
{
	size_t start_pos = confStr.find("!start!");
	size_t end_pos = confStr.find("!end!");

	if (start_pos == std::string::npos || end_pos == std::string::npos)
	{
		outputMessage(_T("Error reading start or end markers"));
		return std::make_tuple(0, 0, false);
	}
	start_pos += 7;

	return std::make_tuple(start_pos, end_pos, true);
}

std::wstring getProcessBinaryPath()
{
	std::wstring binPath;
	HANDLE hProcess = GetCurrentProcess();
	if (!hProcess) return binPath;

	wchar_t szBuffer[MAX_PATH];
	ZeroMemory(szBuffer, sizeof(szBuffer));
	DWORD dwSize = sizeof(szBuffer) / sizeof(szBuffer[0]) - 1;
	QueryFullProcessImageName(hProcess, 0, szBuffer, &dwSize);

	binPath = szBuffer;

	return binPath;
}

std::string extractKeyValueFromConfig(std::string confLine, std::string key)
{
	confLine += (" ");
	size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return "\0";

	size_t nextKeyOffset = confLine.find(" ", keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return "\0";

	return confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());
}

DWORD getConfigVersionNumber(CHAR* buff)
{
	std::string buffString(buff);
	std::string version = extractKeyValueFromConfig(buffString, "ver:");

	if (version.empty())
	{
		return 0;
	}

	return std::stoi(version);
}

std::string addHeaderToBuffer(DWORD verNumber, CHAR* confBuf, DWORD bufSize)
{
	std::string strToHash = confBuf;
	strToHash.resize(bufSize);
	size_t hashValue = std::hash<std::string>{}(strToHash);

	return std::string("ver:" + std::to_string(verNumber) + " hash:" + std::to_string(hashValue) + "\r\n" + "!start!" + strToHash + "!end!");
}

bool createSecurityAttributes(SECURITY_ATTRIBUTES* psa, PSECURITY_DESCRIPTOR psd)
{
	if (InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) != 0)
	{
		if (SetSecurityDescriptorDacl(psd, true, nullptr, false) != 0)
		{
			(*psa).nLength = sizeof(*psa);
			(*psa).lpSecurityDescriptor = psd;
			(*psa).bInheritHandle = false;

			return true;
		}
		else
		{
			outputMessage(TEXT("SetSecurityDescriptorDacl failed : %d.\n"), GetLastError());
		}
	}
	else
	{
		outputMessage(TEXT("InitializeSecurityDescriptor failed : %d.\n"), GetLastError());
	}

	return false;
}

HANDLE createGlobalEvent(bool manualReset, bool initialState, wchar_t* eventName)
{
	HANDLE gEvent = nullptr;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	//TODO: return value instead of passing as ref
	if (createSecurityAttributes(&sa, psd))
	{
		gEvent = CreateEvent(&sa, manualReset, initialState, eventName);
		if (gEvent != nullptr)
		{
			if (ResetEvent(gEvent) == 0)
			{
				std::wstring msg = L"Error: ResetEvent for";
				msg += eventName;
				msg += +L" failed with";
				outputMessage(msg.c_str(), GetLastError());
			}
		}
		else
		{
			std::wstring msg = L"Error: could not create or get a global event ";
			msg += eventName;
			outputMessage(msg.c_str(), GetLastError());
		}
	}

	LocalFree(psd);

	return gEvent;
}

void writeDebugMessage(const wchar_t* msg)
{
	std::wstring dbgMsg = SERVICE_NAME;
	dbgMsg += L" : ";
	dbgMsg += msg;

	OutputDebugString(dbgMsg.c_str());
}

void outputMessage(const wchar_t* msg)
{
	std::wstring msgStr = msg;
	msgStr += L"\n";

	if (interactive) _tprintf(msgStr.c_str());
	else writeDebugMessage(msgStr.c_str());
}

void outputMessage(const wchar_t* msg, DWORD errnum)
{
	std::wstring msgStr = msg;
	msgStr += L" : ";
	msgStr += std::to_wstring(errnum);

	outputMessage(msgStr.c_str());
}

std::wstring getFullPathOfFile(const std::wstring& filename)
{
	wchar_t  filePath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetCurrentDirectory(bufCharCount, filePath))
	{
		outputMessage(TEXT("ERROR: Couldn't get the current directory"), GetLastError());
		return std::wstring();
	}

	return std::wstring(filePath) + _T("\\") + filename;
}
