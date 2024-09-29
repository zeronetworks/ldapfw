#pragma once
#include "stdafx.h"
#include "utils.h"

#define SERVICE_NAME  _T("LDAP Firewall")   
extern HANDLE globalMappedMemory;
extern HANDLE globalUnprotectEvent;
extern bool interactive;

std::wstring getFullPathOfFile(const std::wstring&);

void writeDebugMessage(const wchar_t*);

void outputMessage(const wchar_t*);

void outputMessage(const wchar_t*, DWORD);

bool createSecurityAttributes(SECURITY_ATTRIBUTES*, PSECURITY_DESCRIPTOR);

HANDLE createGlobalEvent(bool, bool, wchar_t*);

void createAllGloblEvents();

void setupNamedPipe();

bool writeToNamedPipe(const std::string);

bool copyDllsToSystemPath();

std::string generateLogPath();

std::string enrichConfig(const std::string&, std::string);

std::string loadConfigFile();

void validateConfigOrExit();

void cleanup();

void installFirewall();

bool startFirewall();

bool stopFirewall();

void uninstallFirewall();

void readConfigAndMapToMemory();

CHAR* readConfigFile(DWORD*);

void printMappedMeomryConfiguration();

std::wstring StringToWString(const std::string&);

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string);