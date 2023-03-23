#pragma once

#define _WIN32_WINNT 0x0602

#define INFO_BUFFER_SIZE 32767
#define MAX_RECORD_BUFFER_SIZE  0x10000 
#define LOW_INTEGRITY_SDDL_SACL_T       TEXT("S:(ML;;NW;;;LW)")
#define LDAP_FW_DLL_NAME TEXT("ldapFW.dll")
#define LDAP_MESSAGES_DLL_NAME TEXT("ldapMessages.dll")
#define SYMBOLS_DIRECTORY TEXT("Symbols")
#define LOG_DIRECTORY TEXT("LDAPFW")
#define LOG_FILENAME TEXT("LDAPFW.log")

#include <Windows.h>
#include <string>
#include <tchar.h>
#include <Tlhelp32.h>
#include <vector>
#include <comdef.h>
#include <sstream>
#include <tuple>

#include "Injections.h"
#include "ldapMessages.h"
#include "elevation.h"