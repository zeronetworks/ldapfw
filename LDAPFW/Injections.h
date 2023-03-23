#pragma once
#include "stdafx.h"

DWORD FindProcessId(const std::wstring& processName);

void hookProcessLoadLibrary(DWORD processID);

bool isDllLoaded(DWORD processID, const WCHAR* dllFullPath);