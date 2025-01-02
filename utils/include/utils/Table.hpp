#pragma once

#include "utils/benchmark/BenchmarkResults.hpp"

#include <string>
#include <vector>

namespace utils
{
class Table
{
public:
    Table(const std::vector<std::string>& headers);

    void addRow(const std::vector<std::string>& row);
    void addRow(const benchmark::BenchmarkResults&, const std::string& name);

    std::string toString() const;
    void print() const;

private:
    std::vector<std::string> headers;
    std::vector<std::vector<std::string>> rows;
};
} // namespace utils