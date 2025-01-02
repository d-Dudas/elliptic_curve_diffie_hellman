#include "utils/Printer.hpp"

#include <iostream>
#include <sstream>

namespace utils
{
Printer::Printer(const std::string name)
: name{name}
{
}

void Printer::operator()(const std::string str)
{
    std::ostringstream oss;
    oss << "[" << name << "] " << str << std::endl;

    std::lock_guard<std::mutex> lock(mtx);
    std::cout << oss.str() << std::flush;
}
} // namespace utils
