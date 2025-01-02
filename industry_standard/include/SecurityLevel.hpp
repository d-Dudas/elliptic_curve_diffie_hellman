#pragma once

#include <cstdint>
#include <string>

enum class SecurityLevel : std::uint8_t
{
    low,
    high
};

std::string getSecurityLevelName(const SecurityLevel);
