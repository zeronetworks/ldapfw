#pragma once
#include "stdafx.h"
#include "config.h"
#include "ldapMessages.h"

bool isOperationInRule(const Rule&, ldapOperation);

std::string stripDomainFromUsername(const std::string&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapAddEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapDelEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapModifyEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapModifyDNEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapSearchEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapCompareEventParameters&);

bool shouldBlockRequest(const std::vector<Rule>&, const LdapExtendedEventParameters&);

std::string getEventAuditMessage(const LdapAddEventParameters&);

std::string getEventAuditMessage(const LdapDelEventParameters&);

std::string getEventAuditMessage(const LdapModifyEventParameters&);

std::string getEventAuditMessage(const LdapModifyDNEventParameters&);

std::string getEventAuditMessage(const LdapSearchEventParameters&);

std::string getEventAuditMessage(const LdapCompareEventParameters&);

std::string getEventAuditMessage(const LdapExtendedEventParameters&);