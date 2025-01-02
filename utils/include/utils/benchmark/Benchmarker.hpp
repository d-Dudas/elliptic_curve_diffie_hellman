#pragma once

#include "utils/benchmark/Timestamp.hpp"
#include "utils/benchmark/BenchmarkResults.hpp"

namespace utils
{
struct Benchmarker
{
    benchmark::Timestamp keyGeneration{};
    benchmark::Timestamp keyExchange{};
    benchmark::Timestamp sharedSecretDerivation{};

    benchmark::BenchmarkResults getResults() const;
};
} // namespace utils
