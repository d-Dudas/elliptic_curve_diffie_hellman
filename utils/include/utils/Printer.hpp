#pragma once

#include <mutex>
#include <string>

namespace utils
{
class Printer
{
public:
    Printer(const std::string name);

    void operator()(const std::string str);

private:
    const std::string name;
    std::mutex mtx;
};
} // namespace utils
