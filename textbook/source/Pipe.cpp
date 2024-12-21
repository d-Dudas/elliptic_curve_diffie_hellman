#include "Pipe.hpp"

#include <cstdint>
#include <unistd.h>

namespace
{
constexpr std::uint8_t writeEnd{1};
constexpr std::uint8_t readEnd{0};
} // namespace

namespace pipeWrapper
{
Pipe::Pipe()
{
    pipe(fileDescriptors);
}

Pipe::~Pipe()
{
    close(fileDescriptors[0]);
    close(fileDescriptors[1]);
}

void Pipe::write(const void* buffer, size_t size)
{
    ::write(fileDescriptors[writeEnd], buffer, size);
}

void Pipe::read(void* buffer, size_t size)
{
    ::read(fileDescriptors[readEnd], buffer, size);
}
} // namespace pipeWrapper
