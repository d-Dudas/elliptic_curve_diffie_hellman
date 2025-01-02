#pragma once

#include <chrono>

namespace utils::benchmark
{
class Timestamp
{
public:
    void start();
    void stop();
    std::chrono::duration<double> getDuration() const;

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> startTimePoint;
    std::chrono::time_point<std::chrono::high_resolution_clock> stopTimePoint;
};
} // namespace utils::benchmark
