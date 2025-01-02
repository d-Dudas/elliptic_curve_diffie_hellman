#include "utils/benchmark/BenchmarkResults.hpp"

namespace utils::benchmark
{
BenchmarkResults average(const BenchmarkResults& lhs, const BenchmarkResults& rhs)
{
    return {
        (lhs.keyGeneration + rhs.keyGeneration) / 2,
        (lhs.keyExchange + rhs.keyExchange) / 2,
        (lhs.sharedSecretDerivation + rhs.sharedSecretDerivation) / 2};
}
} // namespace utils::benchmark
