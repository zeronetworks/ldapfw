#pragma once
#ifdef LIBRARY_EXPORTS
#    define LIBRARY_API __declspec(dllexport)
#else
#    define LIBRARY_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include <iterator>
#include <sstream>

#define GLOBAL_LDAPFW_CONFIG_UPDATE TEXT("Global\\LdapFwUpdateEvent")
#define GLOBAL_LDAPFW_EVENT_UNPROTECT TEXT("Global\\LdapFwUninstalledEvent")
#define GLOBAL_LDAPFW_MANAGER_DONE TEXT("Global\\LdapFwMgrDone")
#define GLOBAL_SHARED_MEMORY TEXT("Global\\LdapFwRules")
#define MEM_BUF_SIZE 0xFFFF

#define DllExport   __declspec( dllexport )

struct LdapAddEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring dn;
	std::vector<std::wstring> entryList;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapDelEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring dn;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapModifyEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring dn;
	std::vector<std::wstring> entryList;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapModifyDNEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring oldDn;
	std::wstring newDn;
	std::wstring deleteOld;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapSearchEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring baseDn;
	std::wstring filter;
	std::wstring scope;
	std::wstring attributes;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapCompareEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring dn;
	std::wstring attribute;
	std::wstring value;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

struct LdapExtendedEventParameters
{
	std::wstring securityId;
	std::wstring action;
	std::wstring oid;
	std::wstring data;
	std::wstring sourceAddress;
	std::wstring sourcePort;
};

DllExport bool deleteEventSource();

DllExport void addEventSource();

DllExport bool ldapProtectedEvent();

DllExport bool ldapUnprotectedEvent();

DllExport bool ldapAddCalledEvent(const LdapAddEventParameters&, bool blockRequest);

DllExport bool ldapDelCalledEvent(const LdapDelEventParameters&, bool blockRequest);

DllExport bool ldapModifyCalledEvent(const LdapModifyEventParameters&, bool blockRequest);

DllExport bool ldapModifyDNCalledEvent(const LdapModifyDNEventParameters&, bool blockRequest);

DllExport bool ldapSearchCalledEvent(const LdapSearchEventParameters&, bool blockRequest);

DllExport bool ldapCompareCalledEvent(const LdapCompareEventParameters&, bool blockRequest);

DllExport bool ldapExtendedCalledEvent(const LdapExtendedEventParameters&, bool blockRequest);

DllExport bool compareCharCaseInsensitive(wchar_t , wchar_t );

DllExport bool compareStringsCaseinsensitive(const wchar_t*, const wchar_t* );

DllExport bool compareStringsCaseinsensitive(const wchar_t* , const wchar_t* , size_t);

DllExport bool checkIfEventConfiguredInReg();

DllExport std::wstring joinUTF8Vector(const std::vector<std::wstring>& v, const std::string delimiter, int end = 1);

template <typename Range, typename Value = typename Range::value_type>
std::wstring JoinW(Range const& elements, const wchar_t* const delimiter) {
	std::wstringstream os;
	auto b = begin(elements), e = end(elements);

	if (b != e) {
		std::copy(b, prev(e), std::ostream_iterator<std::wstring, wchar_t>(os, delimiter));
		b = prev(e);
	}
	if (b != e) {
		os << *b;
	}
	return os.str();
}