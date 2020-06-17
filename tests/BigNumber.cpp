//
// Created by neodar on 30/03/2020.
//

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>

#include "../src/services/Crypto/BigNumber.h"

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
  HCL::Crypto::BigNumber a(9999);
  std::cout << a.TmpDumpHex() << std::endl;
  HCL::Crypto::BigNumber b("32848743298472394723492389", "0123456789");
  std::cout << b.TmpDumpHex() << std::endl;
  HCL::Crypto::BigNumber c = a * b;
  std::cout << c.TmpDumpHex() << std::endl;
  return 0;
}

static int (*big_number_test_functions[])() = {
    BigNumberTest,
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
