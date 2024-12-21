#include <iostream>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "Printer.hpp"

using BigInt = std::int64_t;
using Pipe = int;

class Printer
{
public:
    Printer(std::string name)
    : name(name)
    {
    }

    void print(const std::string str)
    {
        std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "[" << name << "] " << str << std::endl;
    }

private:
    const std::string name;
};

BigInt modExp(BigInt base, BigInt exp, BigInt mod)

{
    BigInt result{1};
    base %= mod;
    while (exp > 0)
    {
        if (exp % 2 == 1)
        {
            result = (result * base) % mod;
        }

        exp >>= 1;
        base = (base * base) % mod;
    }

    return result;
}

BigInt generatePrivateKey(BigInt p)
{
    return std::rand() % (p - 1) + 1;
}

void DiffieHellmanProtocol(
    const BigInt& p,
    const BigInt& g,
    Pipe sendPipe[2],
    Pipe receivePipe[2],
    BigInt& sharedSecret,
    const std::string& name)
{
    Printer printer(name);
    BigInt privateKey = generatePrivateKey(p);
    BigInt publicKey = modExp(g, privateKey, p);
    printer.print("Private Key: " + std::to_string(privateKey));

    write(sendPipe[1], &publicKey, sizeof(publicKey));
    printer.print("Sent Public Key: " + std::to_string(publicKey));

    BigInt receivedPublicKey;
    read(receivePipe[0], &receivedPublicKey, sizeof(receivedPublicKey));
    printer.print("Received Public Key: " + std::to_string(receivedPublicKey));

    sharedSecret = modExp(receivedPublicKey, privateKey, p);
    printer.print("Shared Secret: " + std::to_string(sharedSecret));
}

int main()
{
    std::srand(std::time(nullptr));

    Pipe aliceToBobPipe[2];
    Pipe bobToAlicePipe[2];
    pipe(aliceToBobPipe);
    pipe(bobToAlicePipe);

    const BigInt p{104729};
    const BigInt g{2};

    BigInt sharedSecretAlice;
    BigInt sharedSecretBob;

    std::thread alice(
        DiffieHellmanProtocol, p, g, aliceToBobPipe, bobToAlicePipe, std::ref(sharedSecretAlice), "Alice");
    std::thread bob(DiffieHellmanProtocol, p, g, bobToAlicePipe, aliceToBobPipe, std::ref(sharedSecretBob), "Bob");

    alice.join();
    bob.join();

    std::cout << "Shared Secret Alice: " << sharedSecretAlice << std::endl;
    std::cout << "Shared Secret Bob: " << sharedSecretBob << std::endl;

    return 0;
}
