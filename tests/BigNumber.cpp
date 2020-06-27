//
// Created by neodar on 30/03/2020.
//

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>

#include "../src/services/Crypto/BigNumber.h"
#include "../src/services/Crypto/RandomGenerators/MT19937.h"

//static int AES256KeyExpansionPerformanceTest() {
//  const size_t tests_number = 100000;
//  std::vector<std::array<uint8_t, 32>> keys;
//  std::random_device dev;
//  std::mt19937 rng(dev());
//  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
//  uint8_t result[15][16];
//
//  std::cout << "Generating " << tests_number << " random keys to run Rijndael 256 Key Expansion performance test... "
//            << std::flush;
//  for (int i = 0; i < tests_number; ++i) {
//    keys.emplace_back(std::array<uint8_t, 32>());
//    for (uint8_t &byte : keys[i]) {
//      byte = dist_byte(rng);
//    }
//  }
//  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
//  auto t1 = std::chrono::high_resolution_clock::now();
//  for (auto &key : keys) {
//    HCL::Crypto::RijndaelKeySchedule::KeyExpansion<32, 15>(key.data(), result);
//  }
//  auto t2 = std::chrono::high_resolution_clock::now();
//  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
//  std::cout << "Done! Computed " << tests_number << " Rijndael 256 Key Expansions in " << duration << "us." << std::endl;
//  return 0;
//}

static int BigNumberTest() {
  HCL::Crypto::BigNumber a(89723489783249);
  HCL::Crypto::BigNumber b("90580", "0123456789");
  HCL::Crypto::BigNumber c = a / b;
  std::cout << c.ToBase("0123456789") << std::endl;
  return 0;
}

static int BigNumberModularExponentiation() {
  HCL::Crypto::BigNumber x("2347230479", "0123456789");
  HCL::Crypto::BigNumber exponent("3294823094", "0123456789");
  HCL::Crypto::BigNumber modulo("2349092384", "0123456789");
  HCL::Crypto::BigNumber result = x.ModularExponentiation(exponent, modulo);
  std::cout << result.ToBase("0123456789") << std::endl;
  HCL::Crypto::MT19937 random_generator;
  for (const size_t size : {/*512, */1024/*, 2058, 4096*/}) {
    std::cout << "Testing with " << size << " bits numbers..." << std::endl;
    x = random_generator.GenerateRandomBigNumber(size);
    exponent = random_generator.GenerateRandomBigNumber(size);
    modulo = random_generator.GenerateRandomBigNumber(size);
    std::cout << "x:   " << x.ToBase("01") << std::endl;
    std::cout << "exp: " << exponent.ToBase("01") << std::endl;
    std::cout << "mod: " << modulo.ToBase("01") << std::endl;
    result = x.ModularExponentiation(exponent, modulo);
    std::cout << "res: " << result.ToBase("01") << std::endl;
  }
  return 0;
}

static int BigNumberRandomGeneration() {
  HCL::Crypto::MT19937 random_generator;
  HCL::Crypto::BigNumber a = random_generator.GenerateRandomBigNumber(4096);
  HCL::Crypto::BigNumber b = random_generator.GenerateRandomBigNumber(4096);
  HCL::Crypto::BigNumber c = random_generator.GenerateRandomBigNumber(4096);
  std::cout << "a: " << a.ToBase("0123456789abcdef") << std::endl;
  std::cout << "b: " << b.ToBase("0123456789abcdef") << std::endl;
  std::cout << "c: " << c.ToBase("0123456789abcdef") << std::endl;
  return 0;
}

static int (*big_number_test_functions[])() = {
    BigNumberTest,
    BigNumberModularExponentiation,
    BigNumberRandomGeneration,
    nullptr
};

int BigNumberTests() {
  for (int i = 0; big_number_test_functions[i] != nullptr; ++i) {
    if (big_number_test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
