////////////////////////////////////////
// Events
//
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_RUNTIME                 0x2
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: LDAPFW_AUDIT
//
// MessageText:
//
// LDAP Firewall Audit
//
#define LDAPFW_AUDIT                     ((WORD)0x20000001L)

//
// MessageId: LDAPFW_ADD
//
// MessageText:
//
// LDAP Add Operation
//
#define LDAPFW_ADD                       ((WORD)0x20000002L)

//
// MessageId: LDAPFW_DELETE
//
// MessageText:
//
// LDAP Delete Operation
//
#define LDAPFW_DELETE                    ((WORD)0x20000003L)

//
// MessageId: LDAPFW_MODIFY
//
// MessageText:
//
// LDAP Modify Operation
//
#define LDAPFW_MODIFY                    ((WORD)0x20000004L)

//
// MessageId: LDAPFW_MODIFYDN
//
// MessageText:
//
// LDAP ModifyDN Operation
//
#define LDAPFW_MODIFYDN                  ((WORD)0x20000005L)

//
// MessageId: LDAPFW_SEARCH
//
// MessageText:
//
// LDAP Search Operation
//
#define LDAPFW_SEARCH                    ((WORD)0x20000006L)

//
// MessageId: LDAPFW_COMPARE
//
// MessageText:
//
// LDAP Compare Operation
//
#define LDAPFW_COMPARE                   ((WORD)0x20000007L)

//
// MessageId: LDAPFW_EXTENDED
//
// MessageText:
//
// LDAP Extended Operation
//
#define LDAPFW_EXTENDED                  ((WORD)0x20000008L)

//
// MessageId: LDAP_PROTECTION_ADDED
//
// MessageText:
//
// LDAP Firewall protection installed.
//
#define LDAP_PROTECTION_ADDED            ((DWORD)0x60020101L)

//
// MessageId: LDAP_PROTECTION_REMOVED
//
// MessageText:
//
// LDAP Firewall protection removed.
//
#define LDAP_PROTECTION_REMOVED          ((DWORD)0x60020102L)

//
// MessageId: LDAP_ADD_CALL
//
// MessageText:
//
// An LDAP Add operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tEntry List:%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
//
#define LDAP_ADD_CALL                    ((DWORD)0x60020103L)

//
// MessageId: LDAP_DELETE_CALL
//
// MessageText:
//
// An LDAP Delete operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%nNetwork Information:%n%tClient Network Address:%t%4%n%tClient Port:%t%t%5
//
#define LDAP_DELETE_CALL                 ((DWORD)0x60020104L)

//
// MessageId: LDAP_MODIFY_CALL
//
// MessageText:
//
// An LDAP Modify operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tEntry List:%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
//
#define LDAP_MODIFY_CALL                 ((DWORD)0x60020105L)

//
// MessageId: LDAP_MODIFYDN_CALL
//
// MessageText:
//
// An LDAP Modify DN operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tOld DN:%t%t%t%3%n%tNew DN:%t%t%t%4%n%tDelete Old:%t%t%5%n%nNetwork Information:%n%tClient Network Address:%t%6%n%tClient Port:%t%t%7
//
#define LDAP_MODIFYDN_CALL               ((DWORD)0x60020106L)

//
// MessageId: LDAP_SEARCH_CALL
//
// MessageText:
//
// An LDAP Search operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tBase DN:%t%t%t%3%n%tFilter:%t%t%t%4%n%tScope:%t%t%t%5%n%tAttributes:%t%t%6%n%nNetwork Information:%n%tClient Network Address:%t%7%n%tClient Port:%t%t%8
//
#define LDAP_SEARCH_CALL                 ((DWORD)0x60020107L)

//
// MessageId: LDAP_COMPARE_CALL
//
// MessageText:
//
// An LDAP Compare operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tDN:%t%t%t%3%n%tAttribute:%t%t%4%n%tValue:%t%t%t%5%n%nNetwork Information:%n%tClient Network Address:%t%6%n%tClient Port:%t%t%7
//
#define LDAP_COMPARE_CALL                ((DWORD)0x60020108L)

//
// MessageId: LDAP_EXTENDED_CALL
//
// MessageText:
//
// An LDAP Extended operation was called.%n%nOperation Information:%n%tSecurity ID:%t%t%1%n%tAction:%t%t%t%2%n%tOid:%t%t%t%3%n%tData:%t%t%t%4%n%nNetwork Information:%n%tClient Network Address:%t%5%n%tClient Port:%t%t%6
//
#define LDAP_EXTENDED_CALL               ((DWORD)0x60020109L)

//
// MessageId: LDAP_CONFIG_UPDATED
//
// MessageText:
//
// LDAP Firewall configuration updated.
//
#define LDAP_CONFIG_UPDATED              ((DWORD)0x6002010AL)

