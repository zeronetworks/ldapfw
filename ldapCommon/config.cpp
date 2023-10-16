#include <json/json.h>
#include "stdafx.h"
#include "config.h"
#include "utils.h"

std::vector<std::string> convertJsonArrayToStringVector(const Json::Value& jsonValue)
{
    std::vector<std::string> values;

    for (auto itr : jsonValue) {
        std::string strValue = itr.asString();

        if (strValue == "*") {
            return ANY;
        }
        else {
            values.push_back(itr.asString());
        }
    }

    return values;
}

std::vector<std::string> extractVectorFromJsonArray(const Json::Value& jsonValue, const char* member)
{
    if (jsonValue.isMember(member)) {
        return convertJsonArrayToStringVector(jsonValue[member]);
    }
    else {
        return ANY;
    }
}

ldapOperation convertStringToOperation(std::string opStr)
{
    std::string lowercaseOpStr = StringToLower(opStr);

    if (lowercaseOpStr == "add") return addRequest;
    else if (lowercaseOpStr == "delete") return deleteRequest;
    else if (lowercaseOpStr == "modify") return modifyRequest;
    else if (lowercaseOpStr == "modifydn") return modifyDNRequest;
    else if (lowercaseOpStr == "search") return searchRequest;
    else if (lowercaseOpStr == "compare") return compareRequest;
    else if (lowercaseOpStr == "extended") return extendedRequest;
    else if (lowercaseOpStr == "*") return anyRequest;
    else return unknownRequest;
}

std::vector<ldapOperation> extractOperationFromJsonArray(const Json::Value& jsonValue)
{
    if (!jsonValue.isArray()) {
        return ANYOPERATION;
    }

    std::vector<std::string> opStrArray = convertJsonArrayToStringVector(jsonValue);
    std::vector<ldapOperation> opVector = { };

    for (auto& op : opStrArray) {
        ldapOperation opValue = convertStringToOperation(op);
        if (opValue != unknownRequest) {
            opVector.push_back(opValue);
        }
    }

    if (opVector.size() > 0) {
        return opVector;
    }
    else {
        return ANYOPERATION;
    }
}

action extractActionFromJsonValue(const Json::Value& jsonValue)
{
    std::string actionString = jsonValue.get("action", "allow").asString();

    action Action = allow;

    if (actionString == "block") {
        Action = block;
    }

    return Action;
}

audit extractAuditFromJsonValue(const Json::Value& jsonValue)
{
    std::string auditString = jsonValue.get("audit", "off").asString();

    audit Audit = off;

    if (auditString == "on") {
        Audit = on;
    }

    return Audit;
}

const Json::Value parseStringToJson(const std::string& jsonConfig)
{
    Json::Value root;
    std::stringstream configBuffer;
    configBuffer << jsonConfig;
    configBuffer >> root;
    return root;
}

int getIntFromJsonValue(const Json::Value& jsonValue)
{
    if (jsonValue.isInt()) {
        return jsonValue.asInt();
    }
    else {
        return 0;
    }
}

bool getBoolFromJsonValue(const Json::Value& jsonValue)
{
    if (jsonValue.isBool()) {
        return jsonValue.asBool();
    }
    else {
        return false;
    }
}

std::string getStringFromJsonValue(const Json::Value& jsonValue)
{
    if (jsonValue.isString()) {
        return jsonValue.asString();
    }
    else {
        return std::string();
    }
}

Rule extractRuleFromJsonValue(const Json::Value& ruleJson)
{
    Rule rule = {};

    rule.Operations = extractOperationFromJsonArray(ruleJson["operations"]);
    rule.IPs = extractVectorFromJsonArray(ruleJson, "ips");
    rule.Users = extractVectorFromJsonArray(ruleJson, "users");
    rule.Action = extractActionFromJsonValue(ruleJson);
    rule.Audit = extractAuditFromJsonValue(ruleJson);
    rule.DN = ruleJson.get("dn", "").asString();
    rule.Attributes = extractVectorFromJsonArray(ruleJson, "attributes");
    rule.OID = ruleJson.get("oid", "").asString();
    rule.Filter = ruleJson.get("filter", "").asString();

    return rule;
}

std::vector<Rule> loadRulesFromJson(const Json::Value rulesJson)
{
    std::vector<Rule> rulesVector;

    for (Json::Value::ArrayIndex i = 0; i != rulesJson.size(); i++) {
        Rule rule = extractRuleFromJsonValue(rulesJson[i]);
        rulesVector.push_back(rule);
    }

    return rulesVector;
}

Config loadConfigFromJson(const std::string& jsonConfig)
{
    Config config = {};

    Json::Value root = parseStringToJson(jsonConfig);
    
    if (!root.isObject()) {
        return config;
    }

    const Json::Value rulesJson = root["rules"];
    if (!rulesJson.isArray()) {
        return config;
    }

    config.Rules = loadRulesFromJson(root["rules"]);
    config.DebugLevel = static_cast<logLevel>(getIntFromJsonValue(root["debugLevel"]));
    config.LogPath = getStringFromJsonValue(root["logPath"]);

    const Json::Value offsets = root["offsets"];

    if (!offsets.isObject()) {
        return config;
    }

    config.AddRequestOffset = getIntFromJsonValue(offsets["addRequest"]);
    config.DelRequestOffset = getIntFromJsonValue(offsets["delRequest"]);
    config.ModifyRequestOffset = getIntFromJsonValue(offsets["modifyRequest"]);
    config.ModifyDNRequestOffset = getIntFromJsonValue(offsets["modifyDNRequest"]);
    config.SearchRequestOffset = getIntFromJsonValue(offsets["searchRequest"]);
    config.SearchRequestVersion = getIntFromJsonValue(offsets["searchRequestVersion"]);
    config.CompareRequestOffset = getIntFromJsonValue(offsets["compareRequest"]);
    config.ExtendedRequestOffset = getIntFromJsonValue(offsets["extendedRequest"]);
    config.ExtendedRequestVersion = getIntFromJsonValue(offsets["extendedRequestVersion"]);
    config.InitOffset = getIntFromJsonValue(offsets["init"]);
    config.CleanupOffset = getIntFromJsonValue(offsets["cleanup"]);
    config.SetSecurityContextAttsOffset = getIntFromJsonValue(offsets["setSecurityContextAtts"]);
    config.GetUserNameAOffset = getIntFromJsonValue(offsets["getUserNameA"]);
    config.GetUserSIDFromCurrentTokenOffset = getIntFromJsonValue(offsets["getUserSIDFromCurrentToken"]);

    return config;
}