#pragma once
#include "stdafx.h"
#include <ostream>
#include "utils.h"

enum action
{
    allow = 0,
    block = 1
};

enum audit
{
    off = 0,
    on = 1
};

enum ldapOperation
{
    addRequest,
    deleteRequest,
    modifyRequest,
    modifyDNRequest,
    searchRequest,
    compareRequest,
    extendedRequest,
    anyRequest,
    unknownRequest
};

enum ldapSearchScope
{
    base,
    oneLevel,
    subtree,
    anyScope
};

const std::vector<std::string> ANY = { "*" };
const std::vector<ldapOperation> ANYOPERATION = { anyRequest };
const std::vector<std::wstring> EMPTY_ENTRY_LIST = { };
const std::wstring EMPTY_WSTRING = L"";

struct Rule {
    std::vector<ldapOperation> Operations;
    std::vector<std::string> IPs;
    std::vector<std::string> Users;
    std::vector<std::string> Groups;
    action Action;
    audit Audit;
    std::string DN;
    std::vector<std::string> Attributes;
    std::string OID;
    std::string Filter;
    ldapSearchScope Scope;
};

struct Config {
    std::vector<Rule> Rules;
    int AddRequestOffset;
    int DelRequestOffset;
    int ModifyRequestOffset;
    int ModifyDNRequestOffset;
    int SearchRequestOffset;
    int SearchRequestVersion;
    int CompareRequestOffset;
    int ExtendedRequestOffset;
    int ExtendedRequestVersion;
    int InitOffset;
    int CleanupOffset;
    int SetSecurityContextAttsOffset;
    int GetUserNameAOffset;
    int GetUserSIDFromCurrentTokenOffset;
    int ImpersonateAnyClientOffset;
    int UnImpersonateAnyClientOffset;
    bool DebugLogging;
    std::string LogPath;
};

std::vector<Rule> loadRulesFromJson(const Json::Value);

Config loadConfigFromJson(const std::string&);