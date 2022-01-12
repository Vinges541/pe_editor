#include "util.hpp"

#include <cwctype>


std::string to_string(const BYTE Name[IMAGE_SIZEOF_SHORT_NAME])
{
	std::string result;
	result.resize(IMAGE_SIZEOF_SHORT_NAME);
	std::copy_n(Name, IMAGE_SIZEOF_SHORT_NAME, result.begin());
	if (const auto first_null = result.find_first_of('\0'); first_null != std::string::npos)
	{
		result.resize(first_null);
	}
	return result;
}

bool is_acceptable(wchar_t ch)
{
	return ch == '\b' || std::iswxdigit(ch) != 0;
}