#pragma once

namespace utils
{
#define OPENSSL_CHECK(call)                                                                                     \
    if ((call) <= 0)                                                                                            \
    {                                                                                                           \
        ERR_print_errors_fp(stderr);                                                                            \
        std::string errorMessage{"OpenSSL error at " + std::string{__FILE__} + ":" + std::to_string(__LINE__)}; \
        throw std::runtime_error(errorMessage);                                                                 \
    }

#define OPENSSL_CHECK_NULL(call)                                                                                \
    if ((call) == nullptr)                                                                                      \
    {                                                                                                           \
        ERR_print_errors_fp(stderr);                                                                            \
        std::string errorMessage{"OpenSSL error at " + std::string{__FILE__} + ":" + std::to_string(__LINE__)}; \
        throw std::runtime_error(errorMessage);                                                                 \
    }
} // namespace utils
