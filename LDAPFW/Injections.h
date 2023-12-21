#pragma once
#include "stdafx.h"

DWORD FindProcessId(const std::wstring& processName);

bool hookProcessLoadLibrary(DWORD processID);

bool isDllLoaded(DWORD processID, const WCHAR* dllFullPath);

bool isProcessProtected(const std::wstring&);