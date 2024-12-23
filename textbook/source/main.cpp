#include <iostream>
#include <cstdlib>
#include <thread>
#include <unistd.h>

#include "utils/Printer.hpp"
#include "BigInt.hpp"
#include "Pipe.hpp"
#include "KeyManager.hpp"
#include "Math.hpp"

void DiffieHellmanProtocol(
    const BigInt& p,
    const BigInt& g,
    BigInt& sharedSecret,
    pipeWrapper::write send,
    pipeWrapper::read receive,
    const std::string name)
{
    utils::Printer printLine{name};
    BigInt privateKey{keyManager::generatePrivateKey(p)};
    BigInt publicKey{math::modExp(g, privateKey, p)};
    printLine("Private Key: " + std::to_string(privateKey));

    send(&publicKey, sizeof(publicKey));
    printLine("Sent Public Key: " + std::to_string(publicKey));

    BigInt receivedPublicKey;
    receive(&receivedPublicKey, sizeof(receivedPublicKey));
    printLine("Received Public Key: " + std::to_string(receivedPublicKey));

    sharedSecret = math::modExp(receivedPublicKey, privateKey, p);
    printLine("Shared Secret: " + std::to_string(sharedSecret));
}

int main()
{
    std::srand(std::time(nullptr));
    const BigInt p{104729};
    const BigInt g{2};

    pipeWrapper::Pipe aliceToBobPipe{};
    pipeWrapper::Pipe bobToAlicePipe{};

    BigInt sharedSecretAlice{};
    BigInt sharedSecretBob{};

    pipeWrapper::write writeToAlice{
        std::bind(&pipeWrapper::Pipe::write, &aliceToBobPipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::read readFromAlice{
        std::bind(&pipeWrapper::Pipe::read, &bobToAlicePipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::write writeToBob{
        std::bind(&pipeWrapper::Pipe::write, &bobToAlicePipe, std::placeholders::_1, std::placeholders::_2)};
    pipeWrapper::read readFromBob{
        std::bind(&pipeWrapper::Pipe::read, &aliceToBobPipe, std::placeholders::_1, std::placeholders::_2)};

    std::thread alice{DiffieHellmanProtocol, p, g, std::ref(sharedSecretAlice), writeToBob, readFromBob, "Alice"};
    std::thread bob{DiffieHellmanProtocol, p, g, std::ref(sharedSecretBob), writeToAlice, readFromAlice, "Bob"};

    alice.join();
    bob.join();

    std::cout << "Shared Secret Alice: " << sharedSecretAlice << std::endl;
    std::cout << "Shared Secret Bob: " << sharedSecretBob << std::endl;

    return 0;
}
