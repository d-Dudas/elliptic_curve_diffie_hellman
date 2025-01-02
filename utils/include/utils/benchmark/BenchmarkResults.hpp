#pragma once

#include <chrono>

namespace utils::benchmark
{
struct BenchmarkResults
{
    std::chrono::microseconds keyGeneration{};
    std::chrono::microseconds keyExchange{};
    std::chrono::microseconds sharedSecretDerivation{};
};

BenchmarkResults average(const BenchmarkResults& lhs, const BenchmarkResults& rhs);
} // namespace utils::benchmark
