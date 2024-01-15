#include "ldapMessages.h"
#include "pch.h"
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include "Messages.h"
#include <tchar.h>
#include "ldapMessages.h"
#include <string>
#include <strsafe.h>
#include <codecvt>

#pragma comment(lib, "advapi32.lib")

#define PROVIDER_NAME TEXT("LDAPFW")
#define DLL_PATH TEXT("%SystemRoot%\\system32\\ldapMessages.dll")

HANDLE hEventLog = nullptr;

std::wstring convertUTF8ToWideString(std::string input)
{
    size_t length = input.length();
    std::wstring converted(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), length, &converted[0], length);
    return converted;
}

bool compareCharCaseInsensitive(wchar_t c1, wchar_t c2)
{
    if (c1 == c2)
        return true;
    else if (std::toupper(c1) == std::toupper(c2))
        return true;
    return false;
}

bool compareStringsCaseinsensitive(const wchar_t* str1, const wchar_t* str2)
{
    wchar_t tcharEnd = _T("\0")[0];

    for (int i = 0; i < MAX_PATH; i++)
    {
        if ((str1[i] == tcharEnd) || (str2[i] == tcharEnd))
        {
            break;
        }

        if (!compareCharCaseInsensitive(str1[i], str2[i]))
        {
            return false;
        }
    }
    return true;
}

bool compareStringsCaseinsensitive(const wchar_t* str1, const wchar_t* str2, size_t maxLen)
{
    wchar_t tcharEnd = _T("\0")[0];

    for (size_t i = 0; i < maxLen; i++)
    {
        if ((str1[i] == tcharEnd) || (str2[i] == tcharEnd))
        {
            break;
        }

        if (!compareCharCaseInsensitive(str1[i], str2[i]))
        {
            return false;
        }
    }
    return true;
}

bool regDelNodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    wchar_t szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return true;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            _tprintf(_T("Registry key already deleted.\n"));
            return true;
        }
        else {
            _tprintf(_T("Error opening key.\n"));
            return false;
        }
    }

    lpEnd = lpSubKey + lstrlen(lpSubKey);

    if (*(lpEnd - 1) != TEXT('\\'))
    {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, nullptr,
        nullptr, nullptr, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            if (!regDelNodeRecurse(hKeyRoot, lpSubKey)) {
                break;
            }

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, nullptr,
                nullptr, nullptr, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return true;

    return false;
}

bool deleteEventSource()
{
    wchar_t   szRegPath[MAX_PATH];

    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), PROVIDER_NAME );

    // Create the event source registry key
    return regDelNodeRecurse(HKEY_LOCAL_MACHINE, szRegPath);
}

bool checkIfEventConfiguredInReg()
{
    HKEY    hRegKey = nullptr;
    HKEY    hRegKeyParent = nullptr;
    HKEY  phkResult = nullptr;
    wchar_t   szRegPathParent[MAX_PATH];

    _stprintf_s(szRegPathParent, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), PROVIDER_NAME);

    LSTATUS res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szRegPathParent, 0, KEY_READ, &phkResult);

    if (res != ERROR_SUCCESS)
    {
        return false;
    }
    return true;
}

void addEventSource()
{
    HKEY    hRegKey = nullptr;
    HKEY    hRegKeyParent = nullptr;
    DWORD   dwError = 0;
    wchar_t   szRegPath[MAX_PATH];
    wchar_t   szDLLPath[MAX_PATH];
    wchar_t   szRegPathParent[MAX_PATH];

    _stprintf_s(szRegPathParent, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), PROVIDER_NAME);
    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), PROVIDER_NAME, PROVIDER_NAME);
    _stprintf_s(szDLLPath, _T("%s"), DLL_PATH);

    // Create the event source registry key
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szRegPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_READ | KEY_WRITE | KEY_SET_VALUE, nullptr, &hRegKey, nullptr) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: Couldn't create event source registry key: [%d].\n"), GetLastError());
        return;
    }
        // Name of the PE module that contains the message resource
    if (GetModuleFileName(nullptr, szRegPath, MAX_PATH) == 0)
    {
        _tprintf(TEXT("ERROR: call to GetModuleFileName failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register EventMessageFile
    if (RegSetValueEx(hRegKey, _T("EventMessageFile"), 0, REG_EXPAND_SZ, (PBYTE)szDLLPath, (DWORD)((_tcslen(szDLLPath) + 1) *  (DWORD)sizeof(wchar_t))) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to EventMessageFile failed: [%d].\n"), GetLastError());
        return;
    }

    // Register CategoryMessageFile
    if (RegSetValueEx(hRegKey, _T("CategoryMessageFile"), 0, REG_EXPAND_SZ, (PBYTE)szDLLPath, (DWORD)((_tcslen(szDLLPath) + 1) * (DWORD)sizeof(wchar_t))) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to CategoryMessageFile failed: [%d].\n"), GetLastError());
        return;
    }

    // Register CategoryCount
    DWORD categoriesCount = 8;
    if (RegSetValueEx(hRegKey, _T("CategoryCount"), 0, REG_DWORD, (LPBYTE)&categoriesCount, sizeof(categoriesCount)) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to CategoryCount failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register supported event types
    DWORD dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    if (RegSetValueEx(hRegKey, _T("TypesSupported"), 0, REG_DWORD, (LPBYTE)&dwTypes, sizeof(dwTypes)) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to TypesSupported failed: [%d].\n"), GetLastError());
        return;
    }   

    if (RegOpenKeyW(HKEY_LOCAL_MACHINE, szRegPathParent, &hRegKeyParent) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: getting parent key %s : [%d].\n"), szRegPathParent,GetLastError());
        return;
    }

    DWORD maxSize = 20971520;
    if (RegSetValueEx(hRegKeyParent, _T("MaxSize"), 0, REG_DWORD, (LPBYTE)&maxSize, sizeof(maxSize)) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to MaxSize failed: [%d].\n"), GetLastError());
        return;
    }
    
    _tprintf(TEXT("Finished configuring the Event Log.\n"));
   RegCloseKey(hRegKey);
   
}

bool ldapProtectedEvent()
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);

    if (hEventLog){
       
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            LDAPFW_AUDIT,
            LDAP_PROTECTION_ADDED,           
            nullptr,                       
            0,                          
            0,                          
            NULL,                
            nullptr                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

bool ldapUnprotectedEvent() {

    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            LDAPFW_AUDIT,               
            LDAP_PROTECTION_REMOVED,           
            nullptr,                       
            0,                          
            0,                          
            NULL,                
            nullptr                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

bool ldapConfigUpdateEvent() {

    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            LDAPFW_AUDIT,
            LDAP_CONFIG_UPDATED,
            nullptr,
            0,
            0,
            NULL,
            nullptr
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

std::wstring escapeIpv6Address(const std::wstring& sourceAddress)
{
    std::wstring sourceAddressEscaped = sourceAddress;

    const std::wstring s = _T("\\:");
    const std::wstring t = _T(":");
    std::wstring::size_type n = 0;

    while ((n = sourceAddressEscaped.find(s, n)) != std::string::npos)
    {
        sourceAddressEscaped.replace(n, s.size(), t);
        n += t.size();
    }
    return sourceAddressEscaped;
}

std::wstring joinUTF8Vector(const std::vector<std::wstring>& v, const std::string delimiter, int end)
{
    std::string items = "";
    int vectorLength = v.size();

    for (int i = 0; i < vectorLength; i++) {
        size_t strLength = v[i].length();
        std::string itemStr(strLength, 0);
        WideCharToMultiByte(CP_UTF8, 0, v[i].c_str(), v[i].length(), &itemStr[0], strLength, NULL, NULL);
        items += itemStr;

        if (i < vectorLength - end) {
            items += delimiter;
        }
    }

    return convertUTF8ToWideString(items);
}

bool ldapAddCalledEvent(const LdapAddEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_ADD;
    LPCWSTR aInsertions[6] = {nullptr};
    std::wstring entryListAsWString = joinUTF8Vector(eventParams.entryList, ", ");

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }
      
    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.dn.c_str();
    aInsertions[3] = (wchar_t*)entryListAsWString.c_str();
    aInsertions[4] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[5] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {
        
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            eventCategory,
            LDAP_ADD_CALL,           
            nullptr,                      
            6,                        
            0,                         
            aInsertions,               
            nullptr                       
        );
    }

    return bSuccess;
}

bool ldapDelCalledEvent(const LdapDelEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_DELETE;
    LPCWSTR aInsertions[5] = { nullptr };

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.dn.c_str();
    aInsertions[3] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[4] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_DELETE_CALL,
            nullptr,
            5,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool ldapModifyCalledEvent(const LdapModifyEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_MODIFY;
    LPCWSTR aInsertions[6] = { nullptr };

    std::wstring entryListAsWString = joinUTF8Vector(eventParams.entryList, ", ");

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.dn.c_str();
    aInsertions[3] = (wchar_t*)entryListAsWString.c_str();
    aInsertions[4] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[5] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_MODIFY_CALL,
            nullptr,
            6,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool ldapModifyDNCalledEvent(const LdapModifyDNEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_MODIFYDN;
    LPCWSTR aInsertions[7] = { nullptr };

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.oldDn.c_str();
    aInsertions[3] = (wchar_t*)eventParams.newDn.c_str();
    aInsertions[4] = (wchar_t*)eventParams.deleteOld.c_str();
    aInsertions[5] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[6] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_MODIFYDN_CALL,
            nullptr,
            7,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool ldapSearchCalledEvent(const LdapSearchEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_SEARCH;
    LPCWSTR aInsertions[8] = { nullptr };

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.baseDn.c_str();
    aInsertions[3] = (wchar_t*)eventParams.filter.c_str();
    aInsertions[4] = (wchar_t*)eventParams.scope.c_str();
    aInsertions[5] = (wchar_t*)eventParams.attributes.c_str();
    aInsertions[6] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[7] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_SEARCH_CALL,
            nullptr,
            8,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool ldapCompareCalledEvent(const LdapCompareEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_COMPARE;
    LPCWSTR aInsertions[7] = { nullptr };

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.dn.c_str();
    aInsertions[3] = (wchar_t*)eventParams.attribute.c_str();
    aInsertions[4] = (wchar_t*)eventParams.value.c_str();
    aInsertions[5] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[6] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_COMPARE_CALL,
            nullptr,
            7,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool ldapExtendedCalledEvent(const LdapExtendedEventParameters& eventParams, bool blockRequest)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    DWORD eventCategory = LDAPFW_EXTENDED;
    LPCWSTR aInsertions[6] = { nullptr };

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }

    if (blockRequest) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    aInsertions[0] = (wchar_t*)eventParams.securityId.c_str();
    aInsertions[1] = (wchar_t*)eventParams.action.c_str();
    aInsertions[2] = (wchar_t*)eventParams.oid.c_str();
    aInsertions[3] = (wchar_t*)eventParams.data.c_str();
    aInsertions[4] = (wchar_t*)eventParams.sourceAddress.c_str();
    aInsertions[5] = (wchar_t*)eventParams.sourcePort.c_str();

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,
            eventType,
            eventCategory,
            LDAP_EXTENDED_CALL,
            nullptr,
            6,
            0,
            aInsertions,
            nullptr
        );
    }

    return bSuccess;
}

bool APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            // Close eventlog
            if (hEventLog != nullptr) DeregisterEventSource(hEventLog);
            break;
    }
    return true;
}

