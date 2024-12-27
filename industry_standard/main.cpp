#include "utils/Printer.hpp"
#include "utils/Pipe.hpp"
#include "utils/Check.hpp"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <thread>
#include <iomanip>

std::string toHexString(const std::vector<unsigned char>& data)
{
    std::ostringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (const auto& byte : data)
    {
        hexStream << std::setw(2) << static_cast<int>(byte);
    }
    return hexStream.str();
}

EVP_PKEY* readKeyFromPipe(pipeWrapper::read receive)
{
    size_t keyLength;
    receive(reinterpret_cast<char*>(&keyLength), sizeof(keyLength));

    unsigned char* keyData{new unsigned char[keyLength]};
    receive(reinterpret_cast<char*>(keyData), keyLength);

    BIO* bio{BIO_new_mem_buf(keyData, keyLength)};
    OPENSSL_CHECK_NULL(bio);

    EVP_PKEY* key{PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr)};
    BIO_free(bio);

    delete[] keyData;

    return key;
}

void sendKeyOnPipe(pipeWrapper::write send, EVP_PKEY* key)
{
    BIO* bio{BIO_new(BIO_s_mem())};
    OPENSSL_CHECK_NULL(bio);

    OPENSSL_CHECK(PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr));

    size_t keyLength{static_cast<size_t>(BIO_number_written(bio))};
    send(reinterpret_cast<char*>(&keyLength), sizeof(keyLength));

    unsigned char* keyData{new unsigned char[keyLength]};
    BIO_read(bio, keyData, keyLength);
    send(reinterpret_cast<char*>(keyData), keyLength);

    BIO_free(bio);
    delete[] keyData;
}

void userThread(EVP_PKEY* params, pipeWrapper::write send, pipeWrapper::read receive, const std::string& printerName)
try
{
    utils::Printer print(printerName);

    EVP_PKEY_CTX* kctx{EVP_PKEY_CTX_new(params, nullptr)};
    EVP_PKEY* key{nullptr};

    OPENSSL_CHECK(EVP_PKEY_keygen_init(kctx));
    OPENSSL_CHECK(EVP_PKEY_keygen(kctx, &key));

    print("Key generated.");
    sendKeyOnPipe(send, key);

    EVP_PKEY* peerKey{nullptr};
    peerKey = readKeyFromPipe(receive);
    OPENSSL_CHECK_NULL(peerKey);
    print("Peer key received.");

    EVP_PKEY_CTX* deriveCtx{EVP_PKEY_CTX_new(key, nullptr)};
    OPENSSL_CHECK_NULL(deriveCtx);
    OPENSSL_CHECK(EVP_PKEY_derive_init(deriveCtx));
    OPENSSL_CHECK(EVP_PKEY_derive_set_peer(deriveCtx, peerKey));

    size_t secretLength;
    OPENSSL_CHECK(EVP_PKEY_derive(deriveCtx, nullptr, &secretLength));
    print("Shared secret length: " + std::to_string(secretLength));

    std::vector<unsigned char> secret(secretLength);
    OPENSSL_CHECK(EVP_PKEY_derive(deriveCtx, secret.data(), &secretLength));

    print("Shared secret (hex): " + toHexString(secret));

    EVP_PKEY_free(key);
    EVP_PKEY_free(peerKey);
    EVP_PKEY_CTX_free(kctx);
}
catch (const std::exception& e)
{
    utils::Printer print(printerName + "Error");
    print(e.what());
}

int main()
{
    utils::Printer print("Main");
    print("Diffie-Hellman Key Exchange Example");

    pipeWrapper::Pipe alicePipe;
    pipeWrapper::Pipe bobPipe;

    pipeWrapper::write sendToAlice{
        std::bind(&pipeWrapper::Pipe::write, &alicePipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::read receiveFromAlice{
        std::bind(&pipeWrapper::Pipe::read, &alicePipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::write sendToBob{
        std::bind(&pipeWrapper::Pipe::write, &bobPipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::read receiveFromBob{
        std::bind(&pipeWrapper::Pipe::read, &bobPipe, std::placeholders::_1, std::placeholders::_2)};

    EVP_PKEY_CTX* pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr)};
    OPENSSL_CHECK_NULL(pctx);
    OPENSSL_CHECK(EVP_PKEY_paramgen_init(pctx));

    OPENSSL_CHECK(EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048));
    OPENSSL_CHECK(EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, 2));
    print("Parameters generated.");

    EVP_PKEY* params{nullptr};
    OPENSSL_CHECK(EVP_PKEY_paramgen(pctx, &params));
    print("Parameters set.");

    std::thread aliceThread{userThread, params, sendToBob, receiveFromAlice, "Alice"};
    std::thread bobThread{userThread, params, sendToAlice, receiveFromBob, "Bob"};

    aliceThread.join();
    bobThread.join();

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);

    return 0;
}
