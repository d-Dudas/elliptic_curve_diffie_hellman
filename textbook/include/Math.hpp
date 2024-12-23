#pragma once

#include "BigInt.hpp"

namespace math
{
BigInt modExp(BigInt base, BigInt exp, const BigInt& mod);
} // namespace math
