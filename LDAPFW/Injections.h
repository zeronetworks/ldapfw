#pragma once
#include "stdafx.h"

DWORD FindProcessId(const std::wstring& processName);

bool hookProcessLoadLibrary(DWORD processID);

bool isProcessProtected(const std::wstring&);