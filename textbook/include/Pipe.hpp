#pragma once

#include <cstddef>
#include <functional>

namespace pipeWrapper
{
using write = std::function<void(const void*, size_t)>;
using read = std::function<void(void*, size_t)>;

class Pipe
{
public:
    Pipe();
    ~Pipe();
    void write(const void* buffer, size_t size);
    void read(void* buffer, size_t size);

private:
    int fileDescriptors[2];
};
} // namespace pipeWrapper
