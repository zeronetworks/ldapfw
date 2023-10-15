#pragma once
#include "stdafx.h"
#include "config.h"
#include "ldapMessages.h"

struct RuleAction {
	action Action;
	audit Audit;
};

bool isOperationInRule(const Rule&, ldapOperation);

std::string stripDomainFromUsername(const std::string&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapAddEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapDelEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapModifyEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapModifyDNEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapSearchEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapCompareEventParameters&);

RuleAction getRuleAction(const std::vector<Rule>&, const LdapExtendedEventParameters&);

std::string getEventAuditMessage(const LdapAddEventParameters&);

std::string getEventAuditMessage(const LdapDelEventParameters&);

std::string getEventAuditMessage(const LdapModifyEventParameters&);

std::string getEventAuditMessage(const LdapModifyDNEventParameters&);

std::string getEventAuditMessage(const LdapSearchEventParameters&);

std::string getEventAuditMessage(const LdapCompareEventParameters&);

std::string getEventAuditMessage(const LdapExtendedEventParameters&);