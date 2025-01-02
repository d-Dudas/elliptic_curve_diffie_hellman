#include "utils/benchmark/Timestamp.hpp"

namespace utils::benchmark
{
void Timestamp::start()
{
    startTimePoint = std::chrono::high_resolution_clock::now();
}

void Timestamp::stop()
{
    stopTimePoint = std::chrono::high_resolution_clock::now();
}

std::chrono::duration<double> Timestamp::getDuration() const
{
    return stopTimePoint - startTimePoint;
}
} // namespace utils::benchmark
