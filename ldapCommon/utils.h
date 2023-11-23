#pragma once
const char* const BoolToString(bool b);

std::string StringToLower(std::string);

bool isStringInVector(const std::string*, const std::vector<std::string>&);

std::string wideStringToString(const std::wstring&);

std::wstring stringToWideString(const std::string&);

std::wstring convertUTF8ToWideString(std::string);

std::string convertWideStringToUTF8(std::wstring);

template <typename Range, typename Value = typename Range::value_type>
std::string Join(Range const& elements, const char* const delimiter) {
    std::ostringstream os;
    auto b = begin(elements), e = end(elements);

    if (b != e) {
        std::copy(b, prev(e), std::ostream_iterator<Value>(os, delimiter));
        b = prev(e);
    }
    if (b != e) {
        os << *b;
    }

    return os.str();
}

std::vector<std::string> split(const std::string&, const char*);

std::vector<std::wstring> split(const std::wstring&, const wchar_t*);

std::uint8_t* PatternScan(void*, const char*);

enum logLevel
{
    info = 0,
    debug = 1,
    verbose = 2
};

bool isIPInSubnet(const std::string&, const std::string&, uint8_t);

bool isIPInCIDR(const std::string&, const std::string&);