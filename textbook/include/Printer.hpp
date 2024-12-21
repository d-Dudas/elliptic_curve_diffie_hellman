#pragma once

#include <mutex>
#include <string>

namespace printer
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
} // namespace printer
