#include "SecurityLevel.hpp"

std::string getSecurityLevelName(const SecurityLevel securityLevel)
{
    switch (securityLevel)
    {
        case SecurityLevel::low:
            return "low";
        case SecurityLevel::high:
            return "high";
        default:
            return "Unknown";
    }
}
