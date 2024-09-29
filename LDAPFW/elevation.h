#pragma once

bool tryAndRunElevated(DWORD pid);

bool elevateCurrentProcessToSystem();

bool setSecurityPrivilege(const wchar_t*);