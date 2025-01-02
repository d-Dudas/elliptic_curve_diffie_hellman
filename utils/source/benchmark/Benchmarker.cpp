#include "utils/benchmark/Benchmarker.hpp"

namespace utils
{
benchmark::BenchmarkResults Benchmarker::getResults() const
{
    return {
        std::chrono::duration_cast<std::chrono::microseconds>(keyGeneration.getDuration()),
        std::chrono::duration_cast<std::chrono::microseconds>(keyExchange.getDuration()),
        std::chrono::duration_cast<std::chrono::microseconds>(sharedSecretDerivation.getDuration())};
}
} // namespace utils
