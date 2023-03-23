#include "stdafx.h"
#include "utils.h"
#include <numeric>
#include <string>
#include <sstream>
#include <windows.h>

const char* const BoolToString(bool b)
{
	return b ? "True" : "False";
}

std::string StringToLower(std::string str)
{
	std::string lowerStr = str;

	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
		[](unsigned char c) { return std::tolower(c); });

	return lowerStr;
}

bool isStringInVector(const std::string* s, const std::vector<std::string>& v)
{
	return any_of(v.begin(), v.end(), [&](const std::string& elem) { return elem == (*s); });
}

std::string wideStringToString(const std::wstring& wS)
{
	return std::string(wS.begin(), wS.end());
}

std::wstring stringToWideString(const std::string& s)
{
	return std::wstring(s.begin(), s.end());
}

std::wstring convertUTF8ToWideString(std::string input)
{
    size_t length = input.length();
    std::wstring converted(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), length, &converted[0], length);
    return converted;
}

std::string convertWideStringToUTF8(std::wstring input)
{
    size_t length = input.length();
    std::string converted(length, 0);
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), input.length(), &converted[0], length, NULL, NULL);
    return converted;
}

std::vector<std::wstring> split(const std::wstring& s, const wchar_t* delim) {
    std::wstringstream ss(s);
    std::wstring item;
    std::vector<std::wstring> elems;
    while (std::getline(ss, item, *delim)) {
        elems.push_back(std::move(item));
    }
    return elems;
}