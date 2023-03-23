#include "stdafx.h"
#include <string>
#include <format>
#include <regex>
#include <json/json.h>
#include <ldapMessages.h>
#include "config.h"
#include "utils.h"

bool isOperationInRule(const Rule &rule, ldapOperation op)
{
;    if ((rule.Operations.size() == 1) && (rule.Operations[0] == anyRequest)) {
        return true;
    }

    if (std::find(rule.Operations.begin(), rule.Operations.end(), op) != rule.Operations.end()) {
        return true;
    }

    return false;
}

bool isIPInRule(const Rule& rule, std::string &ip)
{
    for (std::string ruleIP : rule.IPs) {
        if ((ruleIP == ip) || ruleIP == ANY[0])
            return true;
    }

    return false;
}

std::string stripDomainFromUsername(const std::string& user)
{
    size_t position = user.find("\\");

    if (position > 0) {
        return user.substr(position + 1);
    }
    else {
        return user;
    }
}

bool compareUserStrings(std::string userA, std::string userB)
{
    std::string userALower = StringToLower(userA);
    std::string userBLower = StringToLower(userB);

    return userALower == userBLower;
}

bool isUserInRule(const Rule& rule, const std::string& user)
{
    for (std::string ruleUser : rule.Users) {
        if (compareUserStrings(ruleUser, user) || ruleUser == ANY[0])
            return true;
    }

    return false;
}

bool isDNInRule(const Rule& rule, std::string& dn)
{
    if (rule.DN.empty()) {
        return true;
    }
    else if (dn.ends_with(rule.DN)) {
        return true;
    }
    else {
        return false;
    }
}

bool isAttributeInRule(const Rule& rule, const std::vector<std::wstring>& entryList)
{
    if (entryList.size() == 0 || rule.Attribute.empty())
        return true;

    for (std::wstring entry : entryList) {
        size_t pos = entry.find(L":");
        std::wstring attribute = entry.substr(0, pos);

        if (stringToWideString(rule.Attribute) == attribute) {
            return true;
        }
    }

    return false;
}

bool isOidInRule(const Rule& rule, std::string& oid)
{
    if (rule.OID.empty()) {
        return true;
    }
    else if (rule.OID == oid) {
        return true;
    }
    else {
        return false;
    }
}

bool isFilterInRule(const Rule& rule, const std::string& filter)
{
    if (rule.Filter.empty()) {
        return true;
    } else {
        std::regex star_replace("\\*");
        std::regex questionmark_replace("\\?");

        auto wildcard_pattern = regex_replace(
            regex_replace(rule.Filter, star_replace, ".*"),
            questionmark_replace, ".");

        std::regex wildcard_regex("^" + wildcard_pattern + "$");

        return regex_match(filter, wildcard_regex);
    }
}

bool actionToBool(action Action)
{
    if (Action == allow)
        return true;
    else
        return false;
}

bool compareRequestWithRules(const std::vector<Rule>& rules, std::wstring sourceAddress, std::wstring securityId, std::wstring eventDN, ldapOperation op, std::vector<std::wstring> entryList, std::wstring eventOid, std::wstring eventFilter = EMPTY_WSTRING)
{
    for (Rule rule : rules) {
        std::string ip = wideStringToString(sourceAddress);
        std::string user = convertWideStringToUTF8(securityId);
        std::string dn = wideStringToString(eventDN);
        std::string oid = wideStringToString(eventOid);
        std::string filter = wideStringToString(eventFilter);

        bool opInRule = isOperationInRule(rule, op);
        bool ipInRule = isIPInRule(rule, ip);
        bool userInRule = isUserInRule(rule, user);
        bool dnInRule = isDNInRule(rule, dn);
        bool attributeInRule = isAttributeInRule(rule, entryList);
        bool oidInRule = isOidInRule(rule, oid);
        bool filterInRule = isFilterInRule(rule, filter);

        if (opInRule && ipInRule && userInRule && dnInRule && attributeInRule && oidInRule && filterInRule)
            return rule.Action;

    }

    return false;
}

bool shouldBlockRequest(const std::vector<Rule> &rules, const LdapAddEventParameters &eventParams)
{
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.dn, addRequest, eventParams.entryList, EMPTY_WSTRING);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapDelEventParameters& eventParams)
{
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.dn, deleteRequest, EMPTY_ENTRY_LIST, EMPTY_WSTRING);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapModifyEventParameters& eventParams)
{
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.dn, modifyRequest, eventParams.entryList, EMPTY_WSTRING);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapModifyDNEventParameters& eventParams)
{
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.oldDn, modifyDNRequest, EMPTY_ENTRY_LIST, EMPTY_WSTRING);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapSearchEventParameters& eventParams)
{
    std::vector<std::wstring> entryList = { L":" };
    if (!eventParams.attributes.empty()) {
        entryList = split(eventParams.attributes, L";");
    }

    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.baseDn, searchRequest, entryList, EMPTY_WSTRING, eventParams.filter);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapCompareEventParameters& eventParams)
{
    std::vector<std::wstring> entryList = { L":" };
    if (!eventParams.attribute.empty()) {
        entryList = { eventParams.attribute + L":" };
    }
    
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, eventParams.dn, compareRequest, entryList, EMPTY_WSTRING);
}

bool shouldBlockRequest(const std::vector<Rule>& rules, const LdapExtendedEventParameters& eventParams)
{
    return compareRequestWithRules(rules, eventParams.sourceAddress, eventParams.securityId, std::wstring(), extendedRequest, EMPTY_ENTRY_LIST, eventParams.oid);
}

std::string generateLogMessageFromEventParams(std::wstring sourceAddress, std::wstring securityId, std::wstring eventDN, std::wstring op, std::vector<std::wstring> entryList, std::wstring eventOid, std::wstring eventAction, std::wstring eventFilter, std::wstring eventAttributes)
{
    std::vector<std::wstring> eventData;
    std::wstring messagePrefix = std::format(L"{} {} from {}@{} [", eventAction, op, securityId, sourceAddress);

    if (!eventDN.empty()) {
        eventData.push_back(std::format(L"DN: {}", eventDN));
    }

    if (entryList.size() > 0) {
        std::wstring entryListWString = joinUTF8Vector(entryList, ", ");
        eventData.push_back(std::format(L"Entry List: {}", entryListWString));
    }

    if (!eventOid.empty()) {
        eventData.push_back(std::format(L"OID: {}", eventOid));
    }

    if (!eventFilter.empty()) {
        eventData.push_back(std::format(L"Filter: {}", eventFilter));
    }

    if (!eventAttributes.empty()) {
        eventData.push_back(std::format(L"Attributes: {}", eventAttributes));
    }

    eventData.push_back(L"]");
    
    return convertWideStringToUTF8(messagePrefix + joinUTF8Vector(eventData, " \\ ", 2));
}

std::string getEventAuditMessage(const LdapAddEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.dn, L"AddRequest", eventParams.entryList, EMPTY_WSTRING, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}

std::string getEventAuditMessage(const LdapDelEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.dn, L"DeleteRequest", EMPTY_ENTRY_LIST, EMPTY_WSTRING, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}

std::string getEventAuditMessage(const LdapModifyEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.dn, L"ModifyRequest", eventParams.entryList, EMPTY_WSTRING, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}

std::string getEventAuditMessage(const LdapModifyDNEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.oldDn, L"ModifyDNRequest", EMPTY_ENTRY_LIST, EMPTY_WSTRING, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}

std::string getEventAuditMessage(const LdapSearchEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.baseDn, L"SearchRequest", EMPTY_ENTRY_LIST, EMPTY_WSTRING, eventParams.action, eventParams.filter, eventParams.attributes);
}

std::string getEventAuditMessage(const LdapCompareEventParameters& eventParams)
{
    std::vector<std::wstring> entryList = { };

    if (!eventParams.attribute.empty() || !eventParams.value.empty()) {
        std::string entryStr = convertWideStringToUTF8(eventParams.attribute);
        entryStr += "=";
        entryStr += convertWideStringToUTF8(eventParams.value);

        entryList.push_back(convertUTF8ToWideString(entryStr));
    }

    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, eventParams.dn, L"CompareRequest", entryList, EMPTY_WSTRING, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}

std::string getEventAuditMessage(const LdapExtendedEventParameters& eventParams)
{
    return generateLogMessageFromEventParams(eventParams.sourceAddress, eventParams.securityId, EMPTY_WSTRING, L"ExtendedRequest", EMPTY_ENTRY_LIST, eventParams.oid, eventParams.action, EMPTY_WSTRING, EMPTY_WSTRING);
}