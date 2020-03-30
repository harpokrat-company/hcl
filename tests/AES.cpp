//
// Created by neodar on 30/03/2020.
//

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>

#include "../src/services/Crypto/AES.h"

static int CompareData(const uint8_t a[4][4], const uint8_t b[4][4]) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      if (a[i][j] != b[i][j]) {
        return 1;
      }
    }
  }
  return 0;
}

template<uint8_t KeySize>
static void ShowDataError(const uint8_t key[KeySize],
                          const uint8_t expected[4][4],
                          const uint8_t result[4][4]) {
  // TODO Clean display of hex (in separate test output dedicated file)
  std::cerr << "For key: ";
  for (int i = 0; i < KeySize; ++i) {
    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) key[i] << " ";
  }
  std::cerr << std::endl << "Got ciphered data:" << std::endl;
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) result[i][j] << " ";
    }
    std::cerr << std::endl;
  }
  std::cerr << "Instead of correct:" << std::endl;
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) expected[i][j] << " ";
    }
    std::cerr << std::endl;
  }
}

static int AES256Test() {
  const size_t tests_number = 1;
  const uint8_t test_keys[][32] = {
      {
          0xb7, 0x21, 0x7d, 0xec, 0xb2, 0x96, 0x91, 0xfa, 0xd7, 0x34, 0x45, 0x25, 0x3e, 0x32, 0x48, 0xa7,
          0xa3, 0xb4, 0xf6, 0x53, 0xa5, 0xbc, 0xae, 0x57, 0xa0, 0x01, 0x23, 0x08, 0xd6, 0xc3, 0x70, 0xd6,
      }
  };
  uint8_t test_data[][4][4] = {
      {
          {0xf3, 0xe4, 0x84, 0x06},
          {0x3e, 0x3c, 0x4e, 0x38},
          {0x8b, 0xd5, 0x43, 0x65},
          {0x13, 0x1f, 0xb2, 0x77}
      }
  };
  const uint8_t expected_ciphered_data[][4][4] = {
      {
          {0x4d, 0xc1, 0xbc, 0x18},
          {0xc1, 0xea, 0x6a, 0x50},
          {0xe5, 0x28, 0xd7, 0xa7},
          {0xf2, 0x59, 0x3a, 0xfb}
      }
  };
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES128 Rijndael Key Expansion test... "
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

static int (*aes_test_functions[])() = {
    AES256Test,
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
