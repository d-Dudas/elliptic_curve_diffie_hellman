#include "BigInt.hpp"

namespace math
{
BigInt modExp(BigInt base, BigInt exp, const BigInt& mod)
{
    BigInt result{1};
    base %= mod;
    while (exp > 0)
    {
        if (exp % 2 == 1)
        {
            result = (result * base) % mod;
        }

        exp >>= 1;
        base = (base * base) % mod;
    }

    return result;
}
} // namespace math
