#include "BigInt.hpp"

#include <cstdlib>

namespace keyManager
{
BigInt generatePrivateKey(const BigInt& limit)
{
    return std::rand() % (limit - 1) + 1;
}
} // namespace keyManager
