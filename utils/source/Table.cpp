#include "utils/Table.hpp"

#include <iostream>
#include <sstream>

namespace utils
{
Table::Table(const std::vector<std::string>& headers)
: headers{headers}
{
}

void Table::addRow(const std::vector<std::string>& row)
{
    rows.push_back(row);
}

void Table::addRow(const benchmark::BenchmarkResults& results, const std::string& name)
{
    rows.push_back(
        {name,
         std::to_string(results.keyGeneration.count()) + "ms",
         std::to_string(results.keyExchange.count()) + "ms",
         std::to_string(results.sharedSecretDerivation.count()) + "ms"});
}

std::string Table::toString() const
{
    if (headers.empty()) return ""; // Handle empty table case

    std::ostringstream table{}; // Use ostringstream for efficient string concatenation
    table << "\n";

    // Calculate column widths
    std::vector<size_t> columnWidths(headers.size(), 0);
    for (size_t i = 0; i < headers.size(); ++i)
    {
        columnWidths[i] = headers[i].size();
    }
    for (const auto& row : rows)
    {
        for (size_t i = 0; i < row.size(); ++i)
        {
            columnWidths[i] = std::max(columnWidths[i], row[i].size());
        }
    }

    // Helper function to add a row
    auto addRow = [&](const std::vector<std::string>& row)
    {
        table << "|";
        for (size_t i = 0; i < row.size(); ++i)
        {
            table << row[i] << std::string(columnWidths[i] - row[i].size(), ' ') << "|";
        }
        table << "\n";
    };

    // Helper function to add a border
    auto addBorder = [&]()
    {
        table << "+";
        for (size_t width : columnWidths)
        {
            table << std::string(width, '-') << "+";
        }
        table << "\n";
    };

    // Create table
    addBorder(); // Top border
    addRow(headers); // Header row
    addBorder(); // Header-bottom border

    for (const auto& row : rows) // Data rows
    {
        addRow(row);
    }

    addBorder(); // Bottom border

    table << "\n";

    return table.str(); // Convert ostringstream to string
}

void Table::print() const
{
    std::cout << toString();
}
} // namespace utils