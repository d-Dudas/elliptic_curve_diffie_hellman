#include "Printer.hpp"

#include <iostream>

namespace printer
{
Printer::Printer(const std::string name)
: name{name}
{
}

void Printer::operator()(const std::string str)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::cout << "[" << name << "] " << str << std::endl;
}
} // namespace printer
