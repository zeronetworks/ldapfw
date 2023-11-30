// dllmain.cpp : Defines the entry point for the DLL application.
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib,"ws2_32")
#include <Winsock2.h>
#include <rpc.h>
#include "pch.h"
#include <iostream>
#include <sstream>
#include <Windows.h>
#include "psapi.h"
#include <Lmcons.h>
#include <sddl.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <string>
#include <format>
#include <time.h>
#include <json/json.h>
#include <detours.h>
#include <ldapMessages.h>
#include "config.h"
#include "utils.h"
#include "rules.h"

using namespace std;

#define GLOBAL_LDAPFW_EVENT_UNPROTECT TEXT("Global\\LdapFwUninstalledEvent")
#define LDAPFW_PIPE_NAME TEXT("\\\\.\\Pipe\\LDAPFW")
#define PIPE_BUFFER_SIZE 1024
#define MAX_SOCKET_LENGTH 48
#define MAX_NAME 256

int LDAP_INSUFFICIENT_ACCESS = 50;
std::map<uintptr_t, std::string> *ldapConnToSocketMap = new std::map<uintptr_t, std::string>();
std::map<uintptr_t, std::string> *ldapConnToUserMap = new std::map<uintptr_t, std::string>();
HANDLE uninstallEvent = nullptr;
std::string unknownStr = "Unknown";
CRITICAL_SECTION SocketMapCriticalSection;
CRITICAL_SECTION UserMapCriticalSection;

struct GuardCS {
    GuardCS(CRITICAL_SECTION& p_cs) : cs(p_cs) {
        EnterCriticalSection(&cs);
    }
    ~GuardCS() {
        LeaveCriticalSection(&cs);
    }
private:
    GuardCS(GuardCS const&) = delete;
    GuardCS& operator =(GuardCS const&) = delete;
    CRITICAL_SECTION& cs;
};

Config config = { .AddRequestOffset = 0 };

HMODULE myhModule;
HANDLE hPipe;
HMODULE hSrcSrvDll;
HMODULE hSymSrvDll;
HMODULE hDbgHelpDll;

enum Filter: ULONGLONG {
    AndFilter = 1,
    OrFilter = 2,
    NotFilter = 3,
    EqualityFilter = 4,
    SubstringFilter = 5,
    GreaterFilter = 6,
    LessFilter = 7,
    PresenceFilter = 8,
    ApproximateFilter = 9,
    ExtensibleFilter = 10
};

enum SubstringType : ULONGLONG {
    SubInitial = 1,
    SubAny = 2,
    SubFinal = 3
};

struct AddValue {
    std::byte dummy[8];
    size_t lenValue;
    char* pValue;
};

struct AddAttribute {
    AddAttribute* pNext;
    size_t lenAttribute;
    char* pAttribute;
    AddValue* pAddValue;
};

struct LDAPAddMessage {
    std::byte dummy[10];
    size_t lenMessage;
    char* pMessage;
    AddAttribute* pAttribute;
};

struct ModifyValue {
    std::byte dummy[8];
    size_t lenValue;
    char* pValue;
};

struct Attribute {
    Attribute* pNext;
    std::byte dummy[8];
    size_t lenAttribute;
    char* pAttribute;
    ModifyValue* pModifyValue;
};

struct LDAPMessage {
    std::byte dummy[10];
    size_t lenMessage;
    char* pMessage;
    Attribute* pAttribute;
};

struct ModifyDNMessage {
    std::byte dummy[18];
    size_t lenOldDN;
    char* pOldDn;
    size_t lenNewDN;
    char* pNewDn;
    bool deleteOld;
};

struct SearchAttribute {
    SearchAttribute* pNext;
    size_t lenValue;
    char* pValue;
};

typedef union FilterMessage;
struct SingleFilterMessage;
struct LinkedFilterMessage;

struct AndFilterMessage {
    LinkedFilterMessage* pFilterMessage;
    std::byte dummy[56];
};

struct OrFilterMessage {
    LinkedFilterMessage* pFilterMessage;
    std::byte dummy[56];
};

struct NotFilterMessage {
    SingleFilterMessage* pFilterMessage;
    std::byte dummy[56];
};

struct EqualityFilterMessage {
    size_t lenLValue;
    char* pLValue;
    size_t lenRValue;
    char* pRValue;
    std::byte dummy[32];
};

struct SubstringFilterMessageValue {
    SubstringFilterMessageValue* pNextSubstingValue;
    SubstringType substringType;
    size_t lenValue;
    char* pValue;
};

struct SubstringFilterMessage {
    size_t lenValue;
    char* pValue;
    SubstringFilterMessageValue* pSubstringValue;
    std::byte dummy[40];
};

struct GreaterFilterMessage {
    size_t lenLValue;
    char* pLValue;
    size_t lenRValue;
    char* pRValue;
    std::byte dummy[32];
};

struct LessFilterMessage {
    size_t lenLValue;
    char* pLValue;
    size_t lenRValue;
    char* pRValue;
    std::byte dummy[32];
};

struct PresenceFilterMessage {
    size_t lenValue;
    char* pValue;
    std::byte dummy[48];
};

struct ApproximateFilterMessage {
    size_t lenLValue;
    char* pLValue;
    size_t lenRValue;
    char* pRValue;
    std::byte dummy[32];
};

struct ExtensibleFilterMessage {
    std::byte dummy[8];
    size_t lenMatchingRuleOID;
    char* pMatchingRuleOID;
    size_t lenAttribute;
    char* pAttribute;
    size_t lenValue;
    char* pValue;
    std::byte dummy2[8];
};

union FilterMessage
{
    AndFilterMessage andFilterMessage;
    OrFilterMessage orFilterMessage;
    NotFilterMessage notFilterMessage;
    EqualityFilterMessage equalityFilterMessage;
    SubstringFilterMessage substringFilterMessage;
    GreaterFilterMessage greaterFilterMessage;
    LessFilterMessage lessFilterMessage;
    PresenceFilterMessage presenceFilterMessage;
    ApproximateFilterMessage approximateFilterMessage;
    ExtensibleFilterMessage extensibleFilterMessage;
};

struct SingleFilterMessage
{
    Filter filterMessageType;
    FilterMessage filterMessage;
};

union NextFilterMessage
{
    LinkedFilterMessage* pNext;
    ULONGLONG isAttributesOnly;
};

struct LinkedFilterMessage
{
    NextFilterMessage nextMessage;
    SingleFilterMessage filterMessage;
};

struct LDAPSearchMessage {
    std::byte dummy[10];
    size_t lenBaseDn;
    char* pBaseDn;
    ULONGLONG scope;
    std::byte dummy2[8];
    LinkedFilterMessage filterMessage;
    SearchAttribute* pAttribute;
};

struct LDAPCompareMessage {
    std::byte dummy[10];
    size_t lenDn;
    char* pDn;
    size_t lenAttribute;
    char* pAttribute;
    size_t lenValue;
    char* pValue;
};

struct LDAPExtendedMessage {
    std::byte dummy[10];
    size_t lenOid;
    char* pOid;
    size_t lenData;
    wchar_t* pData;
};

int(__thiscall* realAddRequest)(void* pThis, void* thState, void* ldapRequest, LDAPAddMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2);
int(__thiscall* realDelRequest)(void* pThis, void* thState, void* ldapRequest, LDAPMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, int param8);
int(__thiscall* realModifyRequest)(void* pThis, void* thState, void* ldapRequest, LDAPMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2);
int(__thiscall* realModifyDNRequest)(void* pThis, void* thState, void* ldapRequest, ModifyDNMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, int param8);
int(__thiscall* realSearchRequestV1)(void* pThis, void* thState, void* param1, void* param2, void* ldapRequest, ULONG param3, LDAPSearchMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* param4, void** ldapBerval);
int(__thiscall* realSearchRequestV2)(void* pThis, void* thState, void* param1, void* param2, void* ldapRequest, ULONG param3, LDAPSearchMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* searchLogging, void* param4, void** ldapBerval);
int(__thiscall* realCompareRequest)(void* pThis, void* thState, void* ldapRequest, LDAPCompareMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2);
int(__thiscall* realExtendedRequestV4)(void* pThis, void* thState, void* ldapRequest, LDAPExtendedMessage* ldapMsg, void** pReferral, void* ldapString1, void* ldapString2, void* ldapOid, void* ldapString3);
int(__thiscall* realExtendedRequestV5)(void* pThis, void* thState, void* ldapRequest, LDAPExtendedMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* ldapOid, void* ldapString3);
int(__thiscall* realInit)(void* ldapConn, LPSOCKADDR socketAddress, DWORD addressLength, void* atqContextPublic, void* param4);
void(__thiscall* realCleanup)(void* ldapConn);
HRESULT(__thiscall* realSetSecurityContextAtts)(void* ldapConn, void* ldapSecurityContext, ULONG param1, ULONG param2, int param3, void* ldapString);
bool(__thiscall* realGetUserNameA)(void* lpBuffer, void* pcbBuffer);
ULONG(__thiscall* realGetUserSIDFromCurrentToken)(void* thState, PSID Sid);

std::string generateTraceID()
{
    UUID uuid;
    UuidCreate(&uuid);
    char* str;
    UuidToStringA(&uuid, (RPC_CSTR*)&str);
    std::string traceId = str;
    RpcStringFreeA((RPC_CSTR*)&str);
    return traceId;
}

string CurrentDate()
{
    struct tm newtime;
    __time64_t long_time;
    char timebuf[26];
    _time64(&long_time);
    _localtime64_s(&newtime, &long_time);
    asctime_s(timebuf, 26, &newtime);
    timebuf[strlen(timebuf) - 1] = '\0';
    return string(timebuf);
}

SIZE_T getCurrentProcessMemory()
{
    PROCESS_MEMORY_COUNTERS_EX pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    SIZE_T virtualMemUsedByMe = pmc.PrivateUsage;

    return virtualMemUsedByMe;
}

FILE* file;

void write_log(string message)
{
    if (file == NULL) {
        return;
    }

    string message_to_print = "[" + CurrentDate() + "] " + message;
    std::wstring converted = convertUTF8ToWideString(message_to_print);
    //fwprintf(file, converted.c_str());
    fwprintf(file, L"%ls\n", converted.c_str());
    fflush(file);
}

void debug_log(string message, logLevel levelOfLog)
{
    if (config.DebugLevel < levelOfLog) return;

    if (config.DebugLevel == verbose) {
        write_log(std::format("<{} bytes> {}", getCurrentProcessMemory(), message));
    }
    else if (config.DebugLevel == debug) {
        write_log(message);
    }
}

void debug_log(string message, logLevel levelOfLog, string traceId)
{
    if (config.DebugLevel < levelOfLog) return;

    if (config.DebugLevel == verbose) {
        write_log(std::format("({}) <{} bytes> {}", traceId, getCurrentProcessMemory(), message));
    }
    else if (config.DebugLevel == debug) {
        write_log(std::format("({}) {}", traceId, message).c_str());
    }
}

void initialize_logger() {
    if (!config.LogPath.empty() && config.DebugLevel > info) {
        file = _fsopen(config.LogPath.c_str(), "a+, ccs=UTF-8", _SH_DENYNO);
        write_log("Installing LDAPFW...");
    }
}

void close_logger() {
    if (file != NULL) {
        fclose(file);
    }
}

void writeOffsetsToLog()
{
    debug_log(std::format("AddRequest Offset: {}", config.AddRequestOffset), debug);
    debug_log(std::format("DelRequestOffset Offset: {}", config.DelRequestOffset), debug);
    debug_log(std::format("ModifyRequest Offset: {}", config.ModifyRequestOffset), debug);
    debug_log(std::format("ModifyDNRequest Offset: {}", config.ModifyDNRequestOffset), debug);
    debug_log(std::format("SearchRequest Offset: {}", config.SearchRequestOffset), debug);
    debug_log(std::format("CompareRequest Offset: {}", config.CompareRequestOffset), debug);
    debug_log(std::format("ExtendedRequest Offset: {}", config.ExtendedRequestOffset), debug);
    debug_log(std::format("Init Offset: {}", config.InitOffset), debug);
    debug_log(std::format("Cleanup Offset: {}", config.CleanupOffset), debug);
    debug_log(std::format("SetSecurityContextAtts Offset: {}", config.SetSecurityContextAttsOffset), debug);
    debug_log(std::format("GetUserNameA Offset: {}", config.GetUserNameAOffset), debug);
    debug_log(std::format("GetUserSIDFromCurrentToken Offset: {}", config.GetUserSIDFromCurrentTokenOffset), debug);
}

void addToSocketMapping(void* ldapConn, const std::string& socketInfo, std::string traceId)
{
    debug_log(std::format("Adding {} to socket mapping", socketInfo), verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);
    
    {
        GuardCS guard(SocketMapCriticalSection);
        ldapConnToSocketMap->emplace(pointerAddress, socketInfo);
    }

    debug_log(std::format("Added {} to socket mapping", socketInfo), verbose, traceId);
}

std::string getSocketInfoFromLdapConn(void* ldapConn, std::string traceId)
{
    debug_log("Getting from socket mapping", verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);
    std::string socketInfo = unknownStr;

    {
        GuardCS guard(SocketMapCriticalSection);
        if (ldapConnToSocketMap->contains(pointerAddress)) {
            socketInfo = ldapConnToSocketMap->at(pointerAddress);
        }
    }

    debug_log(std::format("Returning socket {} from mapping", socketInfo), verbose, traceId);
    return socketInfo;
}

void removeSocketFromMapping(void* ldapConn, std::string traceId)
{
    debug_log("Removing from socket mapping", verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);

    {
        GuardCS guard(SocketMapCriticalSection);
        ldapConnToSocketMap->erase(pointerAddress);
    }

    debug_log("Removed socket", verbose, traceId);
}

wstring getAccountFromSid(PSID pSid, string traceId) {
    SID_NAME_USE nameUse;
    wchar_t userName[MAX_NAME];
    wchar_t domain[MAX_NAME];
    DWORD dwSize = MAX_NAME;

    if (LookupAccountSidW(NULL, pSid, userName, &dwSize, &domain[0], &dwSize, &nameUse)) {
        wstring userNameW = wstring(userName);
        wstring domainW = wstring(domain);
        debug_log(convertWideStringToUTF8(std::format(L"Parsed account from SID: {}\\{}", domainW, userNameW)), verbose, traceId);
        return domainW + L"\\" + userNameW;
    }
    else {
        debug_log("Unable to find account from sid", verbose, traceId);
        return EMPTY_WSTRING;
    }
}

wstring getAccountOrSidFromTHState(void* thState, string traceId) {
    PSID pSid;
    ULONG getSidResult = realGetUserSIDFromCurrentToken(thState, &pSid);

    if (getSidResult != 0) {
        debug_log("Unable to get user SID", verbose, traceId);
        return EMPTY_WSTRING;
    }

    wstring account = getAccountFromSid(pSid, traceId);
    if (!account.empty()) {
        debug_log(std::format("Found user from SID: {}", convertWideStringToUTF8(account)), verbose, traceId);
        return account;
    }

    wchar_t* stringSid;
    ConvertSidToStringSidW(pSid, &stringSid);
    wstring sidStr = wstring(stringSid);
    debug_log(std::format("Parsed SID: {}", convertWideStringToUTF8(sidStr)), verbose, traceId);
    return sidStr;
}

void addToUserMapping(void* ldapConn, const std::string& userName, std::string traceId, bool overwrite=false)
{
    debug_log(std::format("Adding {} to user mapping", userName), verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);

    {
        GuardCS guard(UserMapCriticalSection);
        if (overwrite) {
            ldapConnToUserMap->insert_or_assign(pointerAddress, userName);
        } else {
            ldapConnToUserMap->emplace(pointerAddress, userName);
        }
    }

    debug_log(std::format("Added {} to user mapping", userName), verbose, traceId);
}

std::string getUserFromLdapConn(void* ldapConn, void* thState, std::string traceId)
{
    debug_log("Getting from user mapping", verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);
    std::string user = unknownStr;

    {
        GuardCS guard(UserMapCriticalSection);
        if (ldapConnToUserMap->contains(pointerAddress)) {
            user = ldapConnToUserMap->at(pointerAddress);
        }
        else {
            debug_log("Unknown user, attempting to resolve from SID", verbose, traceId);
            wstring account = getAccountOrSidFromTHState(thState, traceId);
            if (!account.empty()) {
                user = convertWideStringToUTF8(account);
                addToUserMapping(ldapConn, user, traceId);
            }
        }
    }

    debug_log(std::format("Returning user {} from mapping", user), verbose, traceId);
    return user;
}

void removeUserFromMapping(void* ldapConn, std::string traceId)
{
    debug_log("Removing from user mapping", verbose, traceId);
    std::uintptr_t pointerAddress = reinterpret_cast<std::uintptr_t>(ldapConn);

    {
        GuardCS guard(UserMapCriticalSection);
        ldapConnToUserMap->erase(pointerAddress);
    }

    debug_log("Removed user", verbose, traceId);
}

struct AutoUnloader
{
    ~AutoUnloader()
    {
        write_log("Unloading LDAPFW dll");
        FreeLibraryAndExitThread(myhModule, 0);
    }
};

std::string extractIpFromSocketInfo(const std::string* socketInfo)
{
    if (socketInfo == NULL) return std::string();

    std::string ip = *socketInfo;

    ip.erase(std::remove(ip.begin(), ip.end(), '['), ip.end());
    ip.erase(std::remove(ip.begin(), ip.end(), ']'), ip.end());
    std::string::size_type pos = ip.find_last_of(':');

    if (pos != std::string::npos)
    {
        return ip.substr(0, pos);
    }
    else
    {
        return ip;
    }
}

std::string extractPortFromSocketInfo(const std::string* socketInfo)
{
    if (socketInfo == NULL) return std::string();

    std::string port = *socketInfo;
    std::string::size_type pos = port.find_last_of(':');

    if (pos != std::string::npos)
    {
        return port.substr(pos + 1);
    }
    else
    {
        return port;
    }
}

const std::wstring getActionText(action Action)
{
    if (Action == block) {
        return L"Blocked";
    }
    else {
        return L"Allowed";
    }
}

bool shouldAuditRequest(ldapOperation op, RuleAction ruleAction)
{
    if (ruleAction.Action == block) {
        return true;
    }
    else if (ruleAction.Audit == on) {
        return true;
    }
    else {
        return false;
    }
}

LdapAddEventParameters populateAddEventParameters(void* ldapConn, void* thState, LDAPAddMessage* ldapMsg, std::string traceId)
{
    LdapAddEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());
    eventParams.entryList = std::vector<std::wstring>();


    if (ldapMsg->pMessage == NULL) {
        eventParams.dn = std::wstring();
        return eventParams;
    }
    else {
        string dn(ldapMsg->pMessage, ldapMsg->lenMessage);
        debug_log(std::format("AddRequest DN: {}", dn), verbose, traceId);
        eventParams.dn = convertUTF8ToWideString(dn);
    }

    if (ldapMsg->pAttribute == NULL) {
        return eventParams;
    }

    AddAttribute* addAttribute = ldapMsg->pAttribute;
    string attributeStr(addAttribute->pAttribute, addAttribute->lenAttribute);
    debug_log(std::format("AddRequest Attribute: {}", attributeStr), verbose, traceId);
    std::string entryList = attributeStr + ":";

    if (addAttribute->pAddValue != NULL) {
        AddValue* addValue = addAttribute->pAddValue;
        string valueStr(addValue->pValue, addValue->lenValue);
        debug_log(std::format("AddRequest Value: {}", valueStr), verbose, traceId);
        entryList += valueStr;
    }

    eventParams.entryList.push_back(convertUTF8ToWideString(entryList));

    AddAttribute* pNext = addAttribute->pNext;
    while (pNext) {
        std::string nextEntryList = "";
        if (pNext->pAttribute != NULL) {
            string nextAttributeString(pNext->pAttribute, pNext->lenAttribute);
            debug_log(std::format("AddRequest nextAttribute: {}", nextAttributeString), verbose, traceId);
            nextEntryList += nextAttributeString;
        }

        nextEntryList += ":";
        if (pNext->pAddValue != NULL) {
            AddValue* nextAddValue = pNext->pAddValue;
            string nextValueStr(nextAddValue->pValue, nextAddValue->lenValue);
            debug_log(std::format("AddRequest nextValue: {}", nextValueStr), verbose, traceId);
            nextEntryList += nextValueStr;
        }

        eventParams.entryList.push_back(convertUTF8ToWideString(nextEntryList));
        pNext = pNext->pNext;
    }

    return eventParams;
}

int detouredAddRequest(void* pThis, void* thState, void* ldapRequest, LDAPAddMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2)
{
    std::string traceId = generateTraceID();
    debug_log("Received AddRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapAddEventParameters eventParams = populateAddEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realAddRequest(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2);
    }

    debug_log(getEventAuditMessage(eventParams), debug, traceId);

    if (shouldAuditRequest(addRequest, ruleAction)) {
        ldapAddCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

LdapDelEventParameters populateDelEventParameters(void* ldapConn, void* thState, LDAPMessage* ldapMsg, std::string traceId)
{
    LdapDelEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());

    if (ldapMsg->pMessage != NULL) {
        string dn(ldapMsg->pMessage, ldapMsg->lenMessage);
        debug_log(std::format("DelRequest DN: {}", dn), verbose, traceId);
        eventParams.dn = convertUTF8ToWideString(dn);
    } else {
        eventParams.dn = std::wstring();
    }

    return eventParams;
}

int detouredDelRequest(void* pThis, void* thState, void* ldapRequest, LDAPMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, int param8)
{
    std::string traceId = generateTraceID();
    debug_log("Received DelRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapDelEventParameters eventParams = populateDelEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realDelRequest(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2, param8);
    }

    debug_log(getEventAuditMessage(eventParams), debug, traceId);

    if (shouldAuditRequest(deleteRequest, ruleAction)) {
        ldapDelCalledEvent(eventParams, ruleAction.Action);
        
    }

    return result;
}

LdapModifyEventParameters populateModifyEventParameters(void* ldapConn, void* thState, LDAPMessage* ldapMsg, std::string traceId)
{
    LdapModifyEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());
    eventParams.entryList = std::vector<std::wstring>();

    if (ldapMsg->pMessage == NULL) {
        eventParams.dn = std::wstring();
        return eventParams;
    }
    else {
        string dn(ldapMsg->pMessage, ldapMsg->lenMessage);
        debug_log(std::format("ModifyRequest DN: {}", dn), verbose, traceId);
        eventParams.dn = convertUTF8ToWideString(dn);
    }

    if (ldapMsg->pAttribute == NULL) {
        return eventParams;
    }

    Attribute* modifyAttribute = ldapMsg->pAttribute;
    string attributeStr(modifyAttribute->pAttribute, modifyAttribute->lenAttribute);
    debug_log(std::format("ModifyRequest Attribute: {}", attributeStr), verbose, traceId);
    std::string entryList = attributeStr + ":";

    if (modifyAttribute->pModifyValue != NULL) {
        ModifyValue* modifyValue = modifyAttribute->pModifyValue;
        string valueStr(modifyValue->pValue, modifyValue->lenValue);
        debug_log(std::format("ModifyRequest Value: {}", valueStr), verbose, traceId);
        entryList += valueStr;
    }

    eventParams.entryList.push_back(convertUTF8ToWideString(entryList));

    Attribute* pNext = modifyAttribute->pNext;
    while (pNext) {
        std::string nextEntryList = "";
        if (pNext->pAttribute != NULL) {
            string nextAttributeString(pNext->pAttribute, pNext->lenAttribute);
            debug_log(std::format("ModifyRequest nextAttribute: {}", nextAttributeString), verbose, traceId);
            nextEntryList += nextAttributeString;
        }

        nextEntryList += ":";
        if (pNext->pModifyValue != NULL) {
            ModifyValue* nextModifyValue = pNext->pModifyValue;
            string nextValueStr(nextModifyValue->pValue, nextModifyValue->lenValue);
            debug_log(std::format("ModifyRequest nextValue: {}", nextValueStr), verbose, traceId);
            nextEntryList += nextValueStr;
        }

        eventParams.entryList.push_back(convertUTF8ToWideString(nextEntryList));
        pNext = pNext->pNext;
    }

    return eventParams;
}

int detouredModifyRequest(void* pThis, void* thState, void* ldapRequest, LDAPMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2)
{   
    std::string traceId = generateTraceID();
    debug_log("Received ModifyRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapModifyEventParameters eventParams = populateModifyEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realModifyRequest(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2);
    }

    debug_log(getEventAuditMessage(eventParams), verbose, traceId);
    

    if (shouldAuditRequest(modifyRequest, ruleAction)) {
        ldapModifyCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

LdapModifyDNEventParameters populateModifyDNEventParameters(void* ldapConn, void* thState, ModifyDNMessage* ldapMsg, std::string traceId)
{
    LdapModifyDNEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());

    string oldDN(ldapMsg->pOldDn, ldapMsg->lenOldDN);
    debug_log(std::format("ModifyDNRequest Old DN: {}", oldDN), verbose, traceId);
    eventParams.oldDn = convertUTF8ToWideString(oldDN);

    string newDN(ldapMsg->pNewDn, ldapMsg->lenNewDN);
    debug_log(std::format("ModifyDNRequest New DN: {}", newDN), verbose, traceId);
    eventParams.newDn = convertUTF8ToWideString(newDN);

    string deleteOld = BoolToString(ldapMsg->deleteOld);
    debug_log(std::format("ModifyDNRequest Delete Old: {}", deleteOld), verbose, traceId);
    eventParams.deleteOld = convertUTF8ToWideString(deleteOld);

    return eventParams;
}

int detouredModifyDNRequest(void* pThis, void* thState, void* ldapRequest, ModifyDNMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, int param8)
{
    std::string traceId = generateTraceID();
    debug_log("Received ModifyDNRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapModifyDNEventParameters eventParams = populateModifyDNEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realModifyDNRequest(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2, param8);
    }

    debug_log(getEventAuditMessage(eventParams).c_str(), debug, traceId);

    if (shouldAuditRequest(modifyDNRequest, ruleAction)) {
        ldapModifyDNCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

std::string parseScopeType(ULONGLONG scopeType)
{
    string scope = "Base";
    switch (scopeType) {
    case 1:
        scope = "One Level";
        break;
    case 2:
        scope = "Subtree";
        break;
    }

    return scope;
}

std::string parseFilter(const LinkedFilterMessage& filterMessage, std::string traceId);
std::string parseSingleFilter(const SingleFilterMessage& filterMessage, std::string traceId);

std::string parseAndFilter(const AndFilterMessage& andFilterMessage, std::string traceId) {
    string filterStr = "&";
    if (andFilterMessage.pFilterMessage) {
        filterStr += parseFilter(*andFilterMessage.pFilterMessage, traceId);
    }

    return filterStr;
}

std::string parseOrFilter(const OrFilterMessage& orFilterMessage, std::string traceId) {
    string filterStr = "|";

    if (orFilterMessage.pFilterMessage) {
        filterStr += parseFilter(*orFilterMessage.pFilterMessage, traceId);
    }

    return filterStr;
}

std::string parseNotFilter(const NotFilterMessage& notFilterMessage, std::string traceId) {
    string filterStr = "!";

    if (notFilterMessage.pFilterMessage) {
        filterStr += parseSingleFilter(*notFilterMessage.pFilterMessage, traceId);
    }

    return filterStr;
}

std::string parseEqualityFilter(const EqualityFilterMessage& equalityFilterMessage, std::string traceId) {
    string filterStr = "";

    if (equalityFilterMessage.pLValue) {
        filterStr += string(equalityFilterMessage.pLValue, equalityFilterMessage.lenLValue);
    }

    filterStr += "=";

    if (equalityFilterMessage.pRValue) {
        filterStr += string(equalityFilterMessage.pRValue, equalityFilterMessage.lenRValue);
    }

    return filterStr;
}

std::string parseSubstringFilter(const SubstringFilterMessage& substringFilterMessage, std::string traceId) {
    string filterStr = "";

    if (substringFilterMessage.pValue) {
        filterStr += string(substringFilterMessage.pValue, substringFilterMessage.lenValue);
    }

    filterStr += "=";

    SubstringFilterMessageValue* pSubstringValue = substringFilterMessage.pSubstringValue;

    bool isFirst = true;

    while (pSubstringValue) {
        bool isLast = (pSubstringValue->pNextSubstingValue == NULL);

        if (!pSubstringValue->pValue) {
            continue;
        }

        string component = string(pSubstringValue->pValue, pSubstringValue->lenValue);

        switch (pSubstringValue->substringType) {
        case SubInitial:
        {
            filterStr += component;

            if (isLast)
                filterStr += "*";
        }
        break;
        case SubAny:
        {
            filterStr += "*" + component;

            if (isLast)
                filterStr += "*";
        }
        break;
        case SubFinal:
        {
            if (isFirst || isLast)
                filterStr += "*";

            filterStr += component;
        }
        break;
        }

        pSubstringValue = pSubstringValue->pNextSubstingValue;
        isFirst = false;
    }

    return filterStr;
}

std::string parseGreaterFilter(const GreaterFilterMessage& greaterFilterMessage, std::string traceId) {
    string filterStr = "";

    if (greaterFilterMessage.pLValue) {
        filterStr += string(greaterFilterMessage.pLValue, greaterFilterMessage.lenLValue);
    }

    filterStr += ">=";

    if (greaterFilterMessage.pRValue) {
        filterStr += string(greaterFilterMessage.pRValue, greaterFilterMessage.lenRValue);
    }

    return filterStr;
}

std::string parseLessFilter(const LessFilterMessage& lessFilterMessage, std::string traceId) {
    string filterStr = "";

    if (lessFilterMessage.pLValue) {
        filterStr += string(lessFilterMessage.pLValue, lessFilterMessage.lenLValue);
    }

    filterStr += "<=";

    if (lessFilterMessage.pRValue) {
        filterStr += string(lessFilterMessage.pRValue, lessFilterMessage.lenRValue);
    }

    return filterStr;
}

std::string parsePresenceFilter(const PresenceFilterMessage& presenceFilterMessage, std::string traceId) {
    string filterStr = "";

    if (presenceFilterMessage.pValue) {
        filterStr += string(presenceFilterMessage.pValue, presenceFilterMessage.lenValue);
    }

    return filterStr + "=*";
}

std::string parseApproximateFilter(const ApproximateFilterMessage& approximateFilterMessage, std::string traceId) {
    string filterStr = "";

    if (approximateFilterMessage.pLValue) {
        filterStr += string(approximateFilterMessage.pLValue, approximateFilterMessage.lenLValue);
    }

    filterStr += "~=";

    if (approximateFilterMessage.pRValue) {
        filterStr += string(approximateFilterMessage.pRValue, approximateFilterMessage.lenRValue);
    }

    return filterStr;
}

std::string parseExtensibleFilter(const ExtensibleFilterMessage& extensibleFilterMessage, std::string traceId) {
    string filterStr = "";

    if (extensibleFilterMessage.pAttribute) {
        string attribute = string(extensibleFilterMessage.pAttribute, extensibleFilterMessage.lenAttribute);
        debug_log(std::format("Attribute: {}", attribute), verbose, traceId);
        filterStr += attribute;
    }

    filterStr += ":";

    if (extensibleFilterMessage.pMatchingRuleOID) {
        string ruleOid = string(extensibleFilterMessage.pMatchingRuleOID, extensibleFilterMessage.lenMatchingRuleOID);
        debug_log(std::format("Matching Rule OID: {}", ruleOid), verbose, traceId);
        filterStr += ruleOid + ":";
    }

    if (extensibleFilterMessage.pValue) {
        string value = string(extensibleFilterMessage.pValue, extensibleFilterMessage.lenValue);
        debug_log(std::format("Value: {}", value), verbose, traceId);
        filterStr += "=" + value;
    }

    return filterStr;
}

std::string parseSingleFilter(const SingleFilterMessage& filterMessage, std::string traceId)
{
    string filterStr = "(";

    switch (filterMessage.filterMessageType) {
    case AndFilter:
    {
        debug_log("AND filter", verbose, traceId);
        filterStr += parseAndFilter(filterMessage.filterMessage.andFilterMessage, traceId);
    }

    break;
    case OrFilter:
    {
        debug_log("OR filter", verbose, traceId);
        filterStr += parseOrFilter(filterMessage.filterMessage.orFilterMessage, traceId);
    }
    break;
    case NotFilter:
    {
        debug_log("NOT filter", verbose, traceId);
        filterStr += parseNotFilter(filterMessage.filterMessage.notFilterMessage, traceId);
    }
    break;
    case EqualityFilter:
    {
        debug_log("Equality filter", verbose, traceId);
        filterStr += parseEqualityFilter(filterMessage.filterMessage.equalityFilterMessage, traceId);
    }
    break;
    case SubstringFilter:
    {
        debug_log("Substring filter", verbose, traceId);
        filterStr += parseSubstringFilter(filterMessage.filterMessage.substringFilterMessage, traceId);
    }
    break;
    case GreaterFilter:
    {
        debug_log("Greater-Or-Equal filter", verbose, traceId);
        filterStr += parseGreaterFilter(filterMessage.filterMessage.greaterFilterMessage, traceId);
    }
    break;
    case LessFilter:
    {
        debug_log("Less-Or-Equal filter", verbose, traceId);
        filterStr += parseLessFilter(filterMessage.filterMessage.lessFilterMessage, traceId);
    }
    break;
    case PresenceFilter:
    {
        debug_log("Presence filter", verbose, traceId);
        filterStr += parsePresenceFilter(filterMessage.filterMessage.presenceFilterMessage, traceId);
    }
    break;
    case ApproximateFilter:
    {
        debug_log("Approximate Match filter", verbose, traceId);
        filterStr += parseApproximateFilter(filterMessage.filterMessage.approximateFilterMessage, traceId);
    }
    break;
    case ExtensibleFilter:
    {
        debug_log("Extensible Match filter", verbose, traceId);
        filterStr += parseExtensibleFilter(filterMessage.filterMessage.extensibleFilterMessage, traceId);
    }
    break;
    default:
        debug_log(std::format("Unknown Search filter type: {}", to_string(filterMessage.filterMessageType)), verbose, traceId);
    }

    filterStr += ")";

    debug_log(std::format("Single Filter: {}", filterStr), verbose, traceId);
    return filterStr;
}

std::string parseFilter(const LinkedFilterMessage& filterMessage, std::string traceId)
{
    string filterStr = parseSingleFilter(filterMessage.filterMessage, traceId);

    if (filterMessage.nextMessage.isAttributesOnly == 1) {
        debug_log("Attributes Only search", verbose, traceId);
    }
    else if (filterMessage.nextMessage.pNext) {
        std::stringstream nextStr;
        nextStr << filterMessage.nextMessage.pNext;
        debug_log(std::format("Parsing next subfilter: {}", nextStr.str()), verbose, traceId);
        filterStr += parseFilter(*filterMessage.nextMessage.pNext, traceId);
    }
    
    debug_log(std::format("Linked Filter: {}", filterStr), verbose, traceId);
    return filterStr;
}

LdapSearchEventParameters populateSearchEventParameters(void* ldapConn, void* thState, LDAPSearchMessage* ldapMsg, std::string traceId)
{
    LdapSearchEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());

    string scope = parseScopeType(ldapMsg->scope);
    debug_log(std::format("SearchRequest Scope: {}", scope), verbose, traceId);
    eventParams.scope = stringToWideString(scope);

    string filter = parseFilter(ldapMsg->filterMessage, traceId);
    debug_log(std::format("SearchRequest Filter: {}", filter), verbose, traceId);
    eventParams.filter = convertUTF8ToWideString(filter);

    if (ldapMsg->pBaseDn != NULL) {
        string dn(ldapMsg->pBaseDn, ldapMsg->lenBaseDn);
        debug_log(std::format("SearchRequest DN: {}", dn), verbose, traceId);
        eventParams.baseDn = convertUTF8ToWideString(dn);
    }
    else {
        eventParams.baseDn = std::wstring();
    }

    eventParams.attributes = std::wstring();
    if (ldapMsg->pAttribute != NULL) {
        SearchAttribute* attribute = ldapMsg->pAttribute;

        if (attribute->pValue != NULL) {
            string attributeStr(attribute->pValue, attribute->lenValue);
            debug_log(std::format("SearchRequest Attribute: {}", attributeStr), verbose, traceId);
            eventParams.attributes = convertUTF8ToWideString(attributeStr);
        }

        SearchAttribute* pNext = attribute->pNext;
        while (pNext) {
            if (pNext->pValue != NULL) {
                string nextAttributeStr(pNext->pValue, pNext->lenValue);
                debug_log(std::format("SearchRequest Next Attribute: {}", nextAttributeStr), verbose, traceId);
                eventParams.attributes = eventParams.attributes + L";" + convertUTF8ToWideString(nextAttributeStr);
            }

            pNext = pNext->pNext;
        }
    }

    return eventParams;
}

int detouredSearchRequestV1(void* pThis, void* thState, void* param1, void* param2, void* ldapRequest, ULONG param3, LDAPSearchMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* param4, void** ldapBerval)
{
    std::string traceId = generateTraceID();
    debug_log("Received SearchRequest message", debug, traceId);

    LdapSearchEventParameters eventParams = populateSearchEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == block) {
        ldapMsg->filterMessage.nextMessage.pNext = NULL;
        ldapMsg->filterMessage.filterMessage.filterMessageType = PresenceFilter;
        ldapMsg->filterMessage.filterMessage.filterMessage.presenceFilterMessage.lenValue = 0;
        ldapMsg->filterMessage.filterMessage.filterMessage.presenceFilterMessage.pValue = NULL;
    }

    int result = realSearchRequestV1(pThis, thState, param1, param2, ldapRequest, param3, ldapMsg, pReferral, pControls, ldapString1, ldapString2, param4, ldapBerval);
    debug_log(getEventAuditMessage(eventParams).c_str(), debug, traceId);

    if (shouldAuditRequest(searchRequest, ruleAction)) {
        ldapSearchCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

int detouredSearchRequestV2(void* pThis, void* thState, void* param1, void* param2, void* ldapRequest, ULONG param3, LDAPSearchMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* searchLogging, void* param4, void** ldapBerval)
{
    std::string traceId = generateTraceID();
    debug_log("Received SearchRequest message", debug, traceId);

    LdapSearchEventParameters eventParams = populateSearchEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == block) {
        ldapMsg->filterMessage.nextMessage.pNext = NULL;
        ldapMsg->filterMessage.filterMessage.filterMessageType = PresenceFilter;
        ldapMsg->filterMessage.filterMessage.filterMessage.presenceFilterMessage.lenValue = 0;
        ldapMsg->filterMessage.filterMessage.filterMessage.presenceFilterMessage.pValue = NULL;
    }

    int result = realSearchRequestV2(pThis, thState, param1, param2, ldapRequest, param3, ldapMsg, pReferral, pControls, ldapString1, ldapString2, searchLogging, param4, ldapBerval);
    debug_log(getEventAuditMessage(eventParams), debug, traceId);
    
    if (shouldAuditRequest(searchRequest, ruleAction)) {
        ldapSearchCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

LdapCompareEventParameters populateCompareEventParameters(void* ldapConn, void* thState, LDAPCompareMessage* ldapMsg, std::string traceId)
{
    LdapCompareEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());

    if (ldapMsg->pDn) {
        string dn(ldapMsg->pDn, ldapMsg->lenDn);
        debug_log(std::format("ComareRequest DN: {}", dn), verbose, traceId);
        eventParams.dn = convertUTF8ToWideString(dn);
    }
    else {
        eventParams.dn = std::wstring();
    }

    if (ldapMsg->pAttribute) {
        string attribute(ldapMsg->pAttribute, ldapMsg->lenAttribute);
        debug_log(std::format("ComareRequest Attribute: {}", attribute), verbose, traceId);
        eventParams.attribute = convertUTF8ToWideString(attribute);
    }
    else {
        eventParams.attribute = std::wstring();
    }

    if (ldapMsg->pValue) {
        string value(ldapMsg->pValue, ldapMsg->lenValue);
        debug_log(std::format("ComareRequest Value: {}", value), verbose, traceId);
        eventParams.value = convertUTF8ToWideString(value);
    }
    else {
        eventParams.value = std::wstring();
    }

    return eventParams;
}

int detouredCompareRequest(void* pThis, void* thState, void* ldapRequest, LDAPCompareMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2)
{
    std::string traceId = generateTraceID();
    debug_log("Received CompareRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapCompareEventParameters eventParams = populateCompareEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realCompareRequest(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2);
    }

    debug_log(getEventAuditMessage(eventParams), debug, traceId);

    if (shouldAuditRequest(compareRequest, ruleAction)) {
        ldapCompareCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

LdapExtendedEventParameters populateExtendedEventParameters(void* ldapConn, void* thState, LDAPExtendedMessage* ldapMsg, std::string traceId)
{
    LdapExtendedEventParameters eventParams = {};

    std::string socketInfo = getSocketInfoFromLdapConn(ldapConn, traceId);
    std::string userName = getUserFromLdapConn(ldapConn, thState, traceId);
    std::string ip = extractIpFromSocketInfo(&socketInfo);
    std::string port = extractPortFromSocketInfo(&socketInfo);

    eventParams.securityId = convertUTF8ToWideString(userName);
    eventParams.sourceAddress = std::wstring(ip.begin(), ip.end());
    eventParams.sourcePort = std::wstring(port.begin(), port.end());

    if (ldapMsg->pOid != NULL) {
        string oid(ldapMsg->pOid, ldapMsg->lenOid);
        debug_log(std::format("ExtendedRequest OID: {}", oid), verbose, traceId);
        eventParams.oid = convertUTF8ToWideString(oid);
    }
    else {
        eventParams.oid = std::wstring();
    }

    if (ldapMsg->pData != NULL) {
        wstring data(ldapMsg->pData, ldapMsg->lenData);
        debug_log(std::format("ExtendedRequest Data: {}", convertWideStringToUTF8(data)), verbose, traceId);
        eventParams.data = data;
    }
    else {
        eventParams.data = std::wstring();
    }

    return eventParams;
}

int detouredExtendedRequestV4(void* pThis, void* thState, void* ldapRequest, LDAPExtendedMessage* ldapMsg, void** pReferral, void* ldapString1, void* ldapString2, void* ldapOid, void* ldapString3)
{
    std::string traceId = generateTraceID();
    debug_log("Received ExtendedRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapExtendedEventParameters eventParams = populateExtendedEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realExtendedRequestV4(pThis, thState, ldapRequest, ldapMsg, pReferral, ldapString1, ldapString2, ldapOid, ldapString3);
    }

    debug_log(getEventAuditMessage(eventParams).c_str(), debug, traceId);

    if (shouldAuditRequest(extendedRequest, ruleAction)) {
        ldapExtendedCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

int detouredExtendedRequestV5(void* pThis, void* thState, void* ldapRequest, LDAPExtendedMessage* ldapMsg, void** pReferral, void** pControls, void* ldapString1, void* ldapString2, void* ldapOid, void* ldapString3)
{
    std::string traceId = generateTraceID();
    debug_log("Received ExtendedRequest message", debug, traceId);

    int result = LDAP_INSUFFICIENT_ACCESS;
    LdapExtendedEventParameters eventParams = populateExtendedEventParameters(pThis, thState, ldapMsg, traceId);
    RuleAction ruleAction = getRuleAction(config.Rules, eventParams);
    eventParams.action = getActionText(ruleAction.Action);

    if (ruleAction.Action == allow) {
        result = realExtendedRequestV5(pThis, thState, ldapRequest, ldapMsg, pReferral, pControls, ldapString1, ldapString2, ldapOid, ldapString3);
    }

    debug_log(getEventAuditMessage(eventParams).c_str(), debug, traceId);

    if (shouldAuditRequest(extendedRequest, ruleAction)) {
        ldapExtendedCalledEvent(eventParams, ruleAction.Action);
    }

    return result;
}

int detouredInit(void* ldapConn, LPSOCKADDR socketAddress, DWORD addressLength, void* atqContextPublic, void* param4)
{
    std::string traceId = generateTraceID();
    debug_log("Received new connection", verbose, traceId);

    int result = realInit(ldapConn, socketAddress, addressLength, atqContextPublic, param4);

    if (socketAddress->sa_family != AF_INET && socketAddress->sa_family != AF_INET6) {
        debug_log(std::format("Address type {} is not IPv4/v6", socketAddress->sa_family), verbose, traceId);
        return result;
    }

    if (socketAddress == NULL)
    {
        debug_log("Address is null", verbose, traceId);
        return result;
    }

    char addressBuffer[MAX_SOCKET_LENGTH];
    DWORD addressBufferLength = MAX_SOCKET_LENGTH;
    if (0 == WSAAddressToStringA(socketAddress, addressLength, NULL, addressBuffer, &addressBufferLength)) {
        debug_log(std::format("Parsed IP address: {}", addressBuffer), verbose, traceId);
        addToSocketMapping(ldapConn, addressBuffer, traceId);
    }
    else {
        debug_log("Failed to resolve IP address", verbose, traceId);
    }

    return result;
}

void detouredCleanup(void* ldapConn)
{
    std::string traceId = generateTraceID();
    debug_log("Cleaning connection", verbose, traceId);

    removeSocketFromMapping(ldapConn, traceId);
    removeUserFromMapping(ldapConn, traceId);

    realCleanup(ldapConn);
    debug_log("Connection removed from mapping", verbose, traceId);

    return;
}

HRESULT detouredSetSecurityContextAtts(void* ldapConn, void* ldapSecurityContext, ULONG param1, ULONG param2, int param3, void* ldapString)
{
    std::string traceId = generateTraceID();
    debug_log("Parsing username", verbose, traceId);

    HRESULT result = realSetSecurityContextAtts(ldapConn, ldapSecurityContext, param1, param2, param3, ldapString);
    
    if ((param2 & 2) == 0) {
        debug_log("Cannot parse username", verbose, traceId);
        return result;
    }
    
    wchar_t* userName = nullptr;

    bool success = realGetUserNameA(ldapSecurityContext, &userName);

    if (!success || userName == NULL) {
        debug_log("Failed parsing username", verbose, traceId);
        return result;
    } 

    wstring userW = wstring(userName);
    string out = convertWideStringToUTF8(userW);

    debug_log("Parsed user " + out, verbose, traceId);

    addToUserMapping(ldapConn, out, traceId, true);

    return result;
}

bool getConfigFromNamedPipe()
{
    int maxTime = 5;

    while ((
        hPipe = CreateFile(
            LDAPFW_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL)) == INVALID_HANDLE_VALUE)
    {
        if ((GetLastError() == ERROR_FILE_NOT_FOUND) && maxTime > 0) {
            Sleep(1000);
            maxTime--;
        }
        else {
            CloseHandle(hPipe);
            //std::cout << "Error occurred while connecting to the server: " << GetLastError() << std::endl;
            //write_log("Error occurred while connecting to the server: %d", GetLastError());
            return false;
        }
    }

    char buffer[PIPE_BUFFER_SIZE];
    DWORD cbBytes;
    std::string jsonConfig;

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE) {
        write_log("Invalid NamedPipe handle");
        CloseHandle(hPipe);
        return false;
    }

    BOOL fSuccess = true;

    do
    {
        fSuccess = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &cbBytes, NULL);

        buffer[cbBytes] = '\0';
        jsonConfig += std::string(buffer);

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
            break;


    } while (cbBytes);

    CloseHandle(hPipe);
    
    if (jsonConfig.empty()) {
        write_log(std::format("Config is empty, error: {}", GetLastError()));
        return false;
    }

    Config newConfig;

    try {
        newConfig = loadConfigFromJson(jsonConfig);
    }
    catch (Json::RuntimeError& e) {
        write_log("Config file corrupted, quitting");
        return false;
    }

    if (newConfig.AddRequestOffset == 0 && (config.AddRequestOffset == 0)) {
        write_log("Config missing offsets, quitting");
        return false;
    }
    else if (newConfig.AddRequestOffset > 0 && (config.AddRequestOffset == 0)) {
        config = newConfig;

        if (!config.LogPath.empty()) {
            initialize_logger();
        }

        if (!jsonConfig.empty() && jsonConfig[jsonConfig.length() - 1] == '\n') {
            jsonConfig.erase(jsonConfig.length() - 1);
        }

        write_log("Loaded config");
        debug_log(jsonConfig, debug);
    }
    else {
        config.Rules = newConfig.Rules;
        write_log("Updated rules");
        debug_log(jsonConfig, debug);
    }

    return true;
}

void waitForFurtherInstructions()
{
    uninstallEvent = OpenEvent(SYNCHRONIZE, false, GLOBAL_LDAPFW_EVENT_UNPROTECT);
    WaitForSingleObject(uninstallEvent, 10000);

    if (uninstallEvent == nullptr)
    {
        DWORD errorMessageID = ::GetLastError();
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer); 
        std::string message_with_error_code = errorMessageID + ": " + message;
        write_log(std::format("OpenEvent failed ({}), unloading firewall...", message_with_error_code));
        return;
    }

    bool keepOnSpinning = true;

    while (keepOnSpinning)
    {
        DWORD dwWaitResult = WaitForSingleObject(uninstallEvent, 10000);

        switch (dwWaitResult) {
            case WAIT_OBJECT_0:
                write_log("Unprotect event...");
                keepOnSpinning = false;
                break;
            case WAIT_TIMEOUT:
                getConfigFromNamedPipe();
                break;
            default:
                keepOnSpinning = false;
                write_log("ERROR from WaitForSingleObject");
            }
    }
}

bool isConfigValid() {
    return (config.AddRequestOffset &&
            config.DelRequestOffset &&
            config.ModifyRequestOffset &&
            config.ModifyDNRequestOffset &&
            config.SearchRequestOffset &&
            config.CompareRequestOffset &&
            config.ExtendedRequestOffset &&
            config.ExtendedRequestVersion &&
            config.InitOffset &&
            config.CleanupOffset &&
            config.SetSecurityContextAttsOffset &&
            config.GetUserNameAOffset &&
            config.GetUserSIDFromCurrentTokenOffset &&
            !config.LogPath.empty()
        );
}

void mainStart()
{   
    AutoUnloader autoUnloader;
    InitializeCriticalSection(&SocketMapCriticalSection);
    InitializeCriticalSection(&UserMapCriticalSection);

    if (!getConfigFromNamedPipe() || !isConfigValid()) {
        write_log("Invalid config, uninstalling LDAPFW");
        ldapUnprotectedEvent();
        return;
    }

    writeOffsetsToLog();
       
    uintptr_t base = (uintptr_t)GetModuleHandle(TEXT("ntdsai.dll"));

    realAddRequest = (decltype(realAddRequest))(base + config.AddRequestOffset);
    realDelRequest = (decltype(realDelRequest))(base + config.DelRequestOffset);
    realModifyRequest = (decltype(realModifyRequest))(base + config.ModifyRequestOffset);
    realModifyDNRequest = (decltype(realModifyDNRequest))(base + config.ModifyDNRequestOffset);
    realCompareRequest = (decltype(realCompareRequest))(base + config.CompareRequestOffset);
    realInit = (decltype(realInit))(base + config.InitOffset);
    realCleanup = (decltype(realCleanup))(base + config.CleanupOffset);
    realSetSecurityContextAtts = (decltype(realSetSecurityContextAtts))(base + config.SetSecurityContextAttsOffset);
    realGetUserNameA = (decltype(realGetUserNameA))(base + config.GetUserNameAOffset);
    realGetUserSIDFromCurrentToken = (decltype(realGetUserSIDFromCurrentToken))(base + config.GetUserSIDFromCurrentTokenOffset);
    
    DisableThreadLibraryCalls(myhModule);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (DetourAttach(&(PVOID&)realAddRequest, detouredAddRequest) != NO_ERROR)
    {

    }

    if (DetourAttach(&(PVOID&)realDelRequest, detouredDelRequest) != NO_ERROR)
    {

    }

    if (DetourAttach(&(PVOID&)realModifyRequest, detouredModifyRequest) != NO_ERROR)
    {
 
    }

    if (DetourAttach(&(PVOID&)realModifyDNRequest, detouredModifyDNRequest) != NO_ERROR)
    {

    }

    if (DetourAttach(&(PVOID&)realCompareRequest, detouredCompareRequest) != NO_ERROR)
    {

    }

    if (config.SearchRequestVersion == 1) {
        realSearchRequestV1 = (decltype(realSearchRequestV1))(base + config.SearchRequestOffset);
        if (DetourAttach(&(PVOID&)realSearchRequestV1, detouredSearchRequestV1) != NO_ERROR)
        {

        }
    }
    else  if (config.SearchRequestVersion == 2) {
        realSearchRequestV2 = (decltype(realSearchRequestV2))(base + config.SearchRequestOffset);
        if (DetourAttach(&(PVOID&)realSearchRequestV2, detouredSearchRequestV2) != NO_ERROR)
        {

        }
    }

    if (config.ExtendedRequestVersion == 5) {
        realExtendedRequestV5 = (decltype(realExtendedRequestV5))(base + config.ExtendedRequestOffset);
        if (DetourAttach(&(PVOID&)realExtendedRequestV5, detouredExtendedRequestV5) != NO_ERROR)
        {

        }
    } else  if (config.ExtendedRequestVersion == 4) {
        realExtendedRequestV4 = (decltype(realExtendedRequestV4))(base + config.ExtendedRequestOffset);
        if (DetourAttach(&(PVOID&)realExtendedRequestV4, detouredExtendedRequestV4) != NO_ERROR)
        {

        }
    }


    if (DetourAttach(&(PVOID&)realInit, detouredInit) != NO_ERROR)
    {

    }

    if (DetourAttach(&(PVOID&)realCleanup, detouredCleanup) != NO_ERROR)
    {

    }

    if (DetourAttach(&(PVOID&)realSetSecurityContextAtts, detouredSetSecurityContextAtts) != NO_ERROR)
    {

    }
   
    
    LONG errCode = DetourTransactionCommit();
    if (errCode != NO_ERROR)
    {
    }
    else {
        write_log("LdapFW installed");
        ldapProtectedEvent();
    }

    waitForFurtherInstructions();
}

void dllDetached()
{
    write_log("Detaching LDAP Firewall");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)realAddRequest, detouredAddRequest);
    DetourDetach(&(PVOID&)realDelRequest, detouredDelRequest);
    DetourDetach(&(PVOID&)realModifyRequest, detouredModifyRequest);
    DetourDetach(&(PVOID&)realModifyDNRequest, detouredModifyDNRequest);
    DetourDetach(&(PVOID&)realCompareRequest, detouredCompareRequest);

    if (config.SearchRequestVersion == 1) {
        DetourDetach(&(PVOID&)realSearchRequestV1, detouredSearchRequestV1);
    }
    else if (config.SearchRequestVersion == 2) {
        DetourDetach(&(PVOID&)realSearchRequestV2, detouredSearchRequestV2);
    }

    if (config.ExtendedRequestVersion == 5) {
        DetourDetach(&(PVOID&)realExtendedRequestV5, detouredExtendedRequestV5);
    } else if (config.ExtendedRequestVersion == 4) {
        DetourDetach(&(PVOID&)realExtendedRequestV4, detouredExtendedRequestV4);
    }
    DetourDetach(&(PVOID&)realInit, detouredInit);
    DetourDetach(&(PVOID&)realCleanup, detouredCleanup);
    DetourDetach(&(PVOID&)realSetSecurityContextAtts, detouredSetSecurityContextAtts);

    if (DetourTransactionCommit() == NO_ERROR)
    {
        write_log("LDAP Firewall uninstalled");
        ldapUnprotectedEvent();
    }
    else
    {
        write_log("LDAP Firewall uninstall error: DetourTransactionCommit() failed!");
    }

    ldapConnToSocketMap->clear();
    delete ldapConnToSocketMap;

    ldapConnToUserMap->clear();
    delete ldapConnToUserMap;
}

bool APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            myhModule = hModule;
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mainStart, nullptr, 0, nullptr);
            break;
        case DLL_PROCESS_DETACH:
            dllDetached();
            close_logger();
            break;
    }
    return true;
}