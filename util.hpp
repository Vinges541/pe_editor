#pragma once
#include <algorithm>
#include <sstream>
#include <string>

#include "pe.hpp"

template<typename T>
auto to_string_hex(T value)
{
	std::ostringstream oss;
	oss << std::hex << value;
	return oss.str();
}

template<typename T>
bool is_valid_hex_value(const std::string& value)
{
	if (auto all_chars_valid = std::all_of(value.cbegin(), value.cend(), [](std::string::value_type ch)
		{
			return std::isxdigit(ch) != 0;
		}); !all_chars_valid)
	{
		return false;
	}
		if (value.length() > sizeof T * 2)
		{
			return false;
		}
		return true;
}

template<typename T>
T to_integer(const std::string& str)
{
	std::stringstream ss;
	ss << str;
	T value;
	ss >> std::hex >> value;
	return value;
}

std::string to_string(const BYTE Name[IMAGE_SIZEOF_SHORT_NAME]);

bool is_acceptable(wchar_t ch);