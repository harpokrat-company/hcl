//
// Created by neodar on 30/03/2020.
//

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>

#include "../src/services/Crypto/AES.h"

static int CompareData(const uint8_t a[16], const uint8_t b[16]) {
  for (int i = 0; i < 16; ++i) {
    if (a[i] != b[i]) {
      return 1;
    }
  }
  return 0;
}

template<uint8_t KeySize>
static void ShowDataError(const uint8_t key[KeySize],
                          const uint8_t expected[16],
                          const uint8_t result[16]) {
  // TODO Clean display of hex (in separate test output dedicated file)
  std::cerr << "For key: ";
  for (int i = 0; i < KeySize; ++i) {
    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) key[i] << " ";
  }
  std::cerr << std::endl << "Got ciphered data:" << std::endl;
  for (int i = 0; i < 4; ++i) {
    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) result[i] << " ";
  }
  std::cerr << std::endl;
  std::cerr << "Instead of correct:" << std::endl;
  for (int i = 0; i < 4; ++i) {
    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) expected[i] << " ";
  }
  std::cerr << std::endl;
}

static int AES128Test() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][16] = {
      {0xf6, 0x95, 0xb9, 0x7f, 0x88, 0xcd, 0x9a, 0xb0, 0x8c, 0x8c, 0x03, 0xb3, 0x84, 0xd6, 0x69, 0x84},
      {0x90, 0x8d, 0x44, 0x12, 0xef, 0xc1, 0xe7, 0x29, 0xf1, 0x04, 0xfc, 0x4f, 0x66, 0xae, 0xe6, 0x79},
      {0xd8, 0xee, 0xde, 0xe4, 0x8d, 0x68, 0x01, 0xac, 0xb7, 0xf0, 0x22, 0xe4, 0x5b, 0x1f, 0xe0, 0x24}
  };
  uint8_t test_data[][16] = {
      {0xe8, 0xf2, 0x92, 0x22, 0xda, 0xc9, 0x98, 0x29, 0x38, 0xcd, 0x21, 0xed, 0x3b, 0x04, 0x33, 0x27},
      {0x5e, 0x71, 0x77, 0xb4, 0xde, 0x48, 0x50, 0xfc, 0x74, 0x92, 0xdd, 0xb9, 0xe3, 0xee, 0x56, 0x2a},
      {0x70, 0x6c, 0x36, 0x73, 0x47, 0xe9, 0x6d, 0x63, 0x06, 0x0f, 0x25, 0xec, 0x0a, 0x4b, 0xc9, 0xa2}
  };
  const uint8_t expected_ciphered_data[][16] = {
      {0x8a, 0x5a, 0x0b, 0x72, 0x17, 0xa7, 0xc6, 0x0a, 0x3e, 0xbb, 0xc8, 0x59, 0xf2, 0x95, 0x38, 0x44},
      {0x0b, 0x11, 0xd2, 0x64, 0x05, 0xc3, 0xc9, 0x78, 0xa3, 0x2d, 0xce, 0xb2, 0x6a, 0x80, 0x3c, 0xfd},
      {0x04, 0xd4, 0x83, 0xc3, 0x93, 0x3f, 0x07, 0xe7, 0xf8, 0xf0, 0x60, 0xa6, 0xa2, 0x72, 0xd5, 0x18}
  };
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES 128 block cipher test... "
              << std::flush;
    HCL::Crypto::AES::AES128(test_keys[i], test_data[i]);
    if (CompareData(test_data[i], expected_ciphered_data[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowDataError<16>(test_keys[i], expected_ciphered_data[i], test_data[i]);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES192Test() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][24] = {
      {
          0xff, 0xa6, 0xe9, 0x6d, 0x6f, 0x9d, 0x99, 0x72, 0x71, 0x6e, 0x34, 0xf0, 0x8f, 0x3e, 0xed, 0x0d,
          0xc0, 0x80, 0xf8, 0xf3, 0xa0, 0x4a, 0xd3, 0xae
      },
      {
          0xb8, 0xc7, 0xc1, 0xcb, 0x5f, 0x5e, 0xb6, 0x7b, 0x41, 0x65, 0xef, 0x10, 0x7a, 0x82, 0x0d, 0xab,
          0xc5, 0xfd, 0xb5, 0x11, 0x2b, 0x18, 0x97, 0x32
      },
      {
          0x29, 0xdb, 0xa9, 0x79, 0xa7, 0xbe, 0xe3, 0x26, 0xd3, 0xff, 0xc2, 0x1f, 0xbf, 0xfe, 0x98, 0xef,
          0xee, 0x2f, 0x7e, 0xdb, 0xe4, 0x3f, 0x4f, 0xba
      }
  };
  uint8_t test_data[][16] = {
      {0x8f, 0x40, 0x98, 0x00, 0x43, 0xc7, 0xdb, 0xb4, 0x4a, 0xfd, 0x16, 0x88, 0xcd, 0x29, 0x3e, 0x41},
      {0x99, 0x44, 0x05, 0xe2, 0x5e, 0x58, 0xf8, 0x90, 0xe1, 0x3a, 0x5d, 0xa1, 0xf1, 0xec, 0x48, 0x7b},
      {0xcb, 0x3a, 0xa1, 0x32, 0xb4, 0x1e, 0xd0, 0xe5, 0xb0, 0x6f, 0xb5, 0x37, 0x5a, 0x0b, 0x97, 0xc6}
  };
  const uint8_t expected_ciphered_data[][16] = {
      {0x54, 0x5b, 0x7d, 0x91, 0xd6, 0x90, 0x57, 0x10, 0xe7, 0x79, 0xa3, 0xfe, 0x9d, 0x6e, 0x25, 0xff},
      {0xe7, 0x3b, 0xc2, 0xff, 0xe9, 0x7e, 0x92, 0xb3, 0x32, 0xb5, 0x30, 0xf5, 0x9b, 0x0a, 0x97, 0x76},
      {0x7f, 0x55, 0x24, 0xfc, 0x02, 0xd0, 0x12, 0x9f, 0x40, 0xea, 0xdf, 0xea, 0xd1, 0x47, 0xb1, 0x9c}
  };
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES 192 block cipher test... "
              << std::flush;
    HCL::Crypto::AES::AES192(test_keys[i], test_data[i]);
    if (CompareData(test_data[i], expected_ciphered_data[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowDataError<24>(test_keys[i], expected_ciphered_data[i], test_data[i]);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES256Test() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][32] = {
      {
          0xb7, 0x21, 0x7d, 0xec, 0xb2, 0x96, 0x91, 0xfa, 0xd7, 0x34, 0x45, 0x25, 0x3e, 0x32, 0x48, 0xa7,
          0xa3, 0xb4, 0xf6, 0x53, 0xa5, 0xbc, 0xae, 0x57, 0xa0, 0x01, 0x23, 0x08, 0xd6, 0xc3, 0x70, 0xd6
      },
      {
          0xa1, 0xfd, 0x6d, 0xe4, 0x46, 0xf2, 0x23, 0x98, 0xd7, 0x9c, 0x83, 0xc2, 0xa4, 0xe1, 0x17, 0xe8,
          0xa5, 0x80, 0x6e, 0x8f, 0xe2, 0x1b, 0x7a, 0xa6, 0x5e, 0x63, 0x5d, 0x66, 0x1d, 0x43, 0x8f, 0xd9
      },
      {
          0x08, 0x29, 0x89, 0x50, 0x60, 0xf5, 0xbd, 0x96, 0x20, 0x6d, 0x84, 0xd1, 0x28, 0x4d, 0x21, 0xa9,
          0xd5, 0x49, 0x6d, 0xa5, 0x85, 0xe4, 0xb7, 0x66, 0x68, 0x86, 0x88, 0x8f, 0xe5, 0x1d, 0xef, 0x34
      }
  };
  uint8_t test_data[][16] = {
      {0xf3, 0xe4, 0x84, 0x06, 0x3e, 0x3c, 0x4e, 0x38, 0x8b, 0xd5, 0x43, 0x65, 0x13, 0x1f, 0xb2, 0x77},
      {0xb5, 0xe5, 0xc1, 0x91, 0xa9, 0x6d, 0xaa, 0x31, 0x9b, 0xa7, 0xd8, 0x60, 0xfc, 0x86, 0x5d, 0x9d},
      {0xae, 0x91, 0xb0, 0x9c, 0x3b, 0xa7, 0x95, 0x45, 0x17, 0x6b, 0x1c, 0x8c, 0xe7, 0xf3, 0x99, 0x0e}
  };
  const uint8_t expected_ciphered_data[][16] = {
      {0x4d, 0xc1, 0xbc, 0x18, 0xc1, 0xea, 0x6a, 0x50, 0xe5, 0x28, 0xd7, 0xa7, 0xf2, 0x59, 0x3a, 0xfb},
      {0x6d, 0x04, 0xcc, 0xd2, 0xc2, 0xa4, 0x86, 0x1e, 0xd2, 0x9c, 0x58, 0x17, 0x4a, 0x4e, 0x74, 0xe2},
      {0x64, 0x1a, 0x0b, 0x12, 0x8d, 0x6b, 0xd3, 0xc9, 0x4f, 0x5f, 0xf1, 0x30, 0x2f, 0x90, 0xf1, 0x6a}
  };
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES 256 block cipher test... "
              << std::flush;
    HCL::Crypto::AES::AES256(test_keys[i], test_data[i]);
    if (CompareData(test_data[i], expected_ciphered_data[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowDataError<32>(test_keys[i], expected_ciphered_data[i], test_data[i]);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES128PerformanceTest() {
  const size_t tests_number = 100000;
  std::vector<std::array<uint8_t, 16>> test_keys;
  std::vector<std::array<uint8_t, 16>> test_data;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);

  std::cout << "Generating " << tests_number
            << " random keys and data block to run AES 128 block cipher performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    test_keys.emplace_back(std::array<uint8_t, 16>());
    test_data.emplace_back(std::array<uint8_t, 16>());
    for (uint8_t &byte : test_keys[i]) {
      byte = dist_byte(rng);
    }
    for (uint8_t &byte : test_data[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < tests_number; ++i) {
    HCL::Crypto::AES::AES128(test_keys[i].data(), test_data[i].data());
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 128 block ciphers in " << duration << "us." << std::endl;
  return 0;
}

static int AES192PerformanceTest() {
  const size_t tests_number = 100000;
  std::vector<std::array<uint8_t, 24>> test_keys;
  std::vector<std::array<uint8_t, 16>> test_data;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);

  std::cout << "Generating " << tests_number
            << " random keys and data block to run AES 192 block cipher performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    test_keys.emplace_back(std::array<uint8_t, 24>());
    test_data.emplace_back(std::array<uint8_t, 16>());
    for (uint8_t &byte : test_keys[i]) {
      byte = dist_byte(rng);
    }
    for (uint8_t &byte : test_data[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < tests_number; ++i) {
    HCL::Crypto::AES::AES192(test_keys[i].data(), test_data[i].data());
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 192 block ciphers in " << duration << "us." << std::endl;
  return 0;
}

static int AES256PerformanceTest() {
  const size_t tests_number = 100000;
  std::vector<std::array<uint8_t, 32>> test_keys;
  std::vector<std::array<uint8_t, 16>> test_data;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);

  std::cout << "Generating " << tests_number
            << " random keys and data block to run AES 256 block cipher performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    test_keys.emplace_back(std::array<uint8_t, 32>());
    test_data.emplace_back(std::array<uint8_t, 16>());
    for (uint8_t &byte : test_keys[i]) {
      byte = dist_byte(rng);
    }
    for (uint8_t &byte : test_data[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < tests_number; ++i) {
    HCL::Crypto::AES::AES256(test_keys[i].data(), test_data[i].data());
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 256 block ciphers in " << duration << "us." << std::endl;
  return 0;
}

static int (*aes_test_functions[])() = {
    AES128Test,
    AES192Test,
    AES256Test,
    AES128PerformanceTest,
    AES192PerformanceTest,
    AES256PerformanceTest,
    nullptr
};

int AESTests() {
  for (int i = 0; aes_test_functions[i] != nullptr; ++i) {
    if (aes_test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
