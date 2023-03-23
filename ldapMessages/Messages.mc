SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

FacilityNames=(System=0x0:FACILITY_SYSTEM
               Runtime=0x2:FACILITY_RUNTIME
               Stubs=0x3:FACILITY_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
              )


LanguageNames =
    (
        English = 0x0409:Messages_ENU
    )


;////////////////////////////////////////
;// Events
;//

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=LDAPFW_AUDIT
Language=English
LDAP Firewall Audit
.

MessageId=0x2
SymbolicName=LDAPFW_ADD
Language=English
LDAP Add Operation
.

MessageId=0x3
SymbolicName=LDAPFW_DELETE
Language=English
LDAP Delete Operation
.

MessageId=0x4
SymbolicName=LDAPFW_MODIFY
Language=English
LDAP Modify Operation
.

MessageId=0x5
SymbolicName=LDAPFW_MODIFYDN
Language=English
LDAP ModifyDN Operation
.

MessageId=0x6
SymbolicName=LDAPFW_SEARCH
Language=English
LDAP Search Operation
.

MessageId=0x7
SymbolicName=LDAPFW_COMPARE
Language=English
LDAP Compare Operation
.

MessageId=0x8
SymbolicName=LDAPFW_EXTENDED
Language=English
LDAP Extended Operation
.

MessageIdTypedef=DWORD

MessageId       = 0x101
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_PROTECTION_ADDED
Language        = English
LDAP Firewall protection installed.
.

MessageId       = 0x102
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_PROTECTION_REMOVED
Language        = English
LDAP Firewall protection removed.
.

MessageId       = 0x103
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_ADD_CALL
Language        = English
An LDAP Add operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tEntry List:%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
.

MessageId       = 0x104
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_DELETE_CALL
Language        = English
An LDAP Delete operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%nNetwork Information:%n%tClient Network Address:%t%4%n%tClient Port:%t%t%5
.

MessageId       = 0x105
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_MODIFY_CALL
Language        = English
An LDAP Modify operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tEntry List:%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
.

MessageId       = 0x106
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_MODIFYDN_CALL
Language        = English
An LDAP Modify DN operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tOld DN:%t%t%t%3%n%tNew DN:%t%t%t%4%n%tDelete Old:%t%t%5%n%nNetwork Information:%n%tClient Network Address:%t%6%n%tClient Port:%t%t%7
.

MessageId       = 0x107
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_SEARCH_CALL
Language        = English
An LDAP Search operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tBase DN:%t%t%t%3%n%tFilter:%t%t%t%4%n%tScope:%t%t%t%5%n%tAttributes:%t%t%6%n%nNetwork Information:%n%tClient Network Address:%t%7%n%tClient Port:%t%t%8
.

MessageId       = 0x108
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_COMPARE_CALL
Language        = English
An LDAP Compare operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tAttribute:%t%t%4%n%tValue:%t%t%t%5%n%nNetwork Information:%n%tClient Network Address:%t%6%n%tClient Port:%t%t%7
.

MessageId       = 0x109
Severity        = Informational
Facility        = Runtime
SymbolicName    = LDAP_EXTENDED_CALL
Language        = English
An LDAP Extended operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tOid:%t%t%t%3%n%tData:%t%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
.
