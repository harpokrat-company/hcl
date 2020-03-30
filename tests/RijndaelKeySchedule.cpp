//
// Created by neodar on 30/03/2020.
//

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>

#include "../src/services/Crypto/RijndaelKeySchedule.h"

template<uint8_t RoundKeys>
static int CompareRoundKeys(const uint8_t a[RoundKeys][16], const uint8_t b[RoundKeys][16]) {
  for (int key = 0; key < RoundKeys; ++key) {
    for (int byte = 0; byte < 16; ++byte) {
      if (a[key][byte] != b[key][byte]) {
        return 1;
      }
    }
  }
  return 0;
}

template<uint8_t KeySize, uint8_t RoundKeys>
static void ShowRoundKeyError(const uint8_t key[KeySize],
                       const uint8_t expected[RoundKeys][16],
                       const uint8_t result[RoundKeys][16]) {
  std::cerr << "For key: ";
  for (int i = 0; i < KeySize; ++i) {
    std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) key[i] << " ";
  }
  std::cerr << std::endl << "Got round keys:" << std::endl;
  for (int i = 0; i < RoundKeys; ++i) {
    for (int j = 0; j < 16; ++j) {
      std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) result[i][j] << " ";
    }
    std::cerr << std::endl;
  }
  std::cerr << "Instead of correct:" << std::endl;
  for (int i = 0; i < RoundKeys; ++i) {
    for (int j = 0; j < 16; ++j) {
      std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) expected[i][j] << " ";
    }
    std::cerr << std::endl;
  }
}

static int AES128KeyExpansionTest() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][16] = {
      {
          0x55, 0xce, 0xb0, 0x07, 0x6c, 0x4f, 0x0d, 0xe7, 0x4a, 0x94, 0xd9, 0xc0, 0x8e, 0xcf, 0x69, 0x11
      },
      {
          0x7d, 0x5a, 0xd3, 0x26, 0x54, 0x88, 0x98, 0x30, 0xaf, 0x85, 0x4d, 0xb7, 0xd2, 0xc2, 0xd1, 0xed
      },
      {
          0xff, 0xdc, 0x93, 0xae, 0xac, 0xfe, 0x6d, 0x76, 0x7a, 0x4e, 0xa7, 0x1c, 0x2c, 0x81, 0x63, 0x3c
      }
  };
  const uint8_t expected_round_keys[][11][16] = {
      {
          {0x55, 0xce, 0xb0, 0x07, 0x6c, 0x4f, 0x0d, 0xe7, 0x4a, 0x94, 0xd9, 0xc0, 0x8e, 0xcf, 0x69, 0x11},
          {0xde, 0x37, 0x32, 0x1e, 0xb2, 0x78, 0x3f, 0xf9, 0xf8, 0xec, 0xe6, 0x39, 0x76, 0x23, 0x8f, 0x28},
          {0xfa, 0x44, 0x06, 0x26, 0x48, 0x3c, 0x39, 0xdf, 0xb0, 0xd0, 0xdf, 0xe6, 0xc6, 0xf3, 0x50, 0xce},
          {0xf3, 0x17, 0x8d, 0x92, 0xbb, 0x2b, 0xb4, 0x4d, 0x0b, 0xfb, 0x6b, 0xab, 0xcd, 0x08, 0x3b, 0x65},
          {0xcb, 0xf5, 0xc0, 0x2f, 0x70, 0xde, 0x74, 0x62, 0x7b, 0x25, 0x1f, 0xc9, 0xb6, 0x2d, 0x24, 0xac},
          {0x03, 0xc3, 0x51, 0x61, 0x73, 0x1d, 0x25, 0x03, 0x08, 0x38, 0x3a, 0xca, 0xbe, 0x15, 0x1e, 0x66},
          {0x7a, 0xb1, 0x62, 0xcf, 0x09, 0xac, 0x47, 0xcc, 0x01, 0x94, 0x7d, 0x06, 0xbf, 0x81, 0x63, 0x60},
          {0x36, 0x4a, 0xb2, 0xc7, 0x3f, 0xe6, 0xf5, 0x0b, 0x3e, 0x72, 0x88, 0x0d, 0x81, 0xf3, 0xeb, 0x6d},
          {0xbb, 0xa3, 0x8e, 0xcb, 0x84, 0x45, 0x7b, 0xc0, 0xba, 0x37, 0xf3, 0xcd, 0x3b, 0xc4, 0x18, 0xa0},
          {0xbc, 0x0e, 0x6e, 0x29, 0x38, 0x4b, 0x15, 0xe9, 0x82, 0x7c, 0xe6, 0x24, 0xb9, 0xb8, 0xfe, 0x84},
          {0xe6, 0xb5, 0x31, 0x7f, 0xde, 0xfe, 0x24, 0x96, 0x5c, 0x82, 0xc2, 0xb2, 0xe5, 0x3a, 0x3c, 0x36}
      },
      {
          {0x7d, 0x5a, 0xd3, 0x26, 0x54, 0x88, 0x98, 0x30, 0xaf, 0x85, 0x4d, 0xb7, 0xd2, 0xc2, 0xd1, 0xed},
          {0x59, 0x64, 0x86, 0x93, 0x0d, 0xec, 0x1e, 0xa3, 0xa2, 0x69, 0x53, 0x14, 0x70, 0xab, 0x82, 0xf9},
          {0x39, 0x77, 0x1f, 0xc2, 0x34, 0x9b, 0x01, 0x61, 0x96, 0xf2, 0x52, 0x75, 0xe6, 0x59, 0xd0, 0x8c},
          {0xf6, 0x07, 0x7b, 0x4c, 0xc2, 0x9c, 0x7a, 0x2d, 0x54, 0x6e, 0x28, 0x58, 0xb2, 0x37, 0xf8, 0xd4},
          {0x64, 0x46, 0x33, 0x7b, 0xa6, 0xda, 0x49, 0x56, 0xf2, 0xb4, 0x61, 0x0e, 0x40, 0x83, 0x99, 0xda},
          {0x98, 0xa8, 0x64, 0x72, 0x3e, 0x72, 0x2d, 0x24, 0xcc, 0xc6, 0x4c, 0x2a, 0x8c, 0x45, 0xd5, 0xf0},
          {0xd6, 0xab, 0xe8, 0x16, 0xe8, 0xd9, 0xc5, 0x32, 0x24, 0x1f, 0x89, 0x18, 0xa8, 0x5a, 0x5c, 0xe8},
          {0x28, 0xe1, 0x73, 0xd4, 0xc0, 0x38, 0xb6, 0xe6, 0xe4, 0x27, 0x3f, 0xfe, 0x4c, 0x7d, 0x63, 0x16},
          {0x57, 0x1a, 0x34, 0xfd, 0x97, 0x22, 0x82, 0x1b, 0x73, 0x05, 0xbd, 0xe5, 0x3f, 0x78, 0xde, 0xf3},
          {0xf0, 0x07, 0x39, 0x88, 0x67, 0x25, 0xbb, 0x93, 0x14, 0x20, 0x06, 0x76, 0x2b, 0x58, 0xd8, 0x85},
          {0xac, 0x66, 0xae, 0x79, 0xcb, 0x43, 0x15, 0xea, 0xdf, 0x63, 0x13, 0x9c, 0xf4, 0x3b, 0xcb, 0x19}
      },
      {
          {0xff, 0xdc, 0x93, 0xae, 0xac, 0xfe, 0x6d, 0x76, 0x7a, 0x4e, 0xa7, 0x1c, 0x2c, 0x81, 0x63, 0x3c},
          {0xf2, 0x27, 0x78, 0xdf, 0x5e, 0xd9, 0x15, 0xa9, 0x24, 0x97, 0xb2, 0xb5, 0x08, 0x16, 0xd1, 0x89},
          {0xb7, 0x19, 0xdf, 0xef, 0xe9, 0xc0, 0xca, 0x46, 0xcd, 0x57, 0x78, 0xf3, 0xc5, 0x41, 0xa9, 0x7a},
          {0x30, 0xca, 0x05, 0x49, 0xd9, 0x0a, 0xcf, 0x0f, 0x14, 0x5d, 0xb7, 0xfc, 0xd1, 0x1c, 0x1e, 0x86},
          {0xa4, 0xb8, 0x41, 0x77, 0x7d, 0xb2, 0x8e, 0x78, 0x69, 0xef, 0x39, 0x84, 0xb8, 0xf3, 0x27, 0x02},
          {0xb9, 0x74, 0x36, 0x1b, 0xc4, 0xc6, 0xb8, 0x63, 0xad, 0x29, 0x81, 0xe7, 0x15, 0xda, 0xa6, 0xe5},
          {0xce, 0x50, 0xef, 0x42, 0x0a, 0x96, 0x57, 0x21, 0xa7, 0xbf, 0xd6, 0xc6, 0xb2, 0x65, 0x70, 0x23},
          {0xc3, 0x01, 0xc9, 0x75, 0xc9, 0x97, 0x9e, 0x54, 0x6e, 0x28, 0x48, 0x92, 0xdc, 0x4d, 0x38, 0xb1},
          {0xa0, 0x06, 0x01, 0xf3, 0x69, 0x91, 0x9f, 0xa7, 0x07, 0xb9, 0xd7, 0x35, 0xdb, 0xf4, 0xef, 0x84},
          {0x04, 0xd9, 0x5e, 0x4a, 0x6d, 0x48, 0xc1, 0xed, 0x6a, 0xf1, 0x16, 0xd8, 0xb1, 0x05, 0xf9, 0x5c},
          {0x59, 0x40, 0x14, 0x82, 0x34, 0x08, 0xd5, 0x6f, 0x5e, 0xf9, 0xc3, 0xb7, 0xef, 0xfc, 0x3a, 0xeb}
      }
  };
  uint8_t result[11][16] = {};
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES128 Rijndael Key Expansion test... "
              << std::flush;
    HCL::Crypto::RijndaelKeySchedule::AES128KeyExpansion(test_keys[i], result);
    if (CompareRoundKeys<11>(result, expected_round_keys[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowRoundKeyError<16, 11>(test_keys[i], expected_round_keys[i], result);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES192KeyExpansionTest() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][24] = {
      {
          0x9b, 0x79, 0x19, 0x5d, 0xce, 0xd0, 0x9c, 0x05, 0xa1, 0xc2, 0xcd, 0xda, 0x99, 0x56, 0xc2, 0x76,
          0xfc, 0x5a, 0xf0, 0x75, 0xc7, 0xf5, 0x44, 0x36
      },
      {
          0xb7, 0xe9, 0xf3, 0xd1, 0xe2, 0xf9, 0x2f, 0x1a, 0x8f, 0x35, 0xc6, 0x2f, 0x5d, 0xce, 0x67, 0x7a,
          0xb1, 0x9e, 0x49, 0xbd, 0x02, 0x70, 0xde, 0xe2
      },
      {
          0xa9, 0x57, 0x19, 0x06, 0x6e, 0x71, 0xf5, 0x26, 0x0b, 0x1c, 0x30, 0xc0, 0xa4, 0xe9, 0x0d, 0xf7,
          0x3d, 0xdc, 0xce, 0x29, 0x56, 0x45, 0xd5, 0x3e
      }
  };
  const uint8_t expected_round_keys[][13][16] = {
      {
          {0x9b, 0x79, 0x19, 0x5d, 0xce, 0xd0, 0x9c, 0x05, 0xa1, 0xc2, 0xcd, 0xda, 0x99, 0x56, 0xc2, 0x76},
          {0xfc, 0x5a, 0xf0, 0x75, 0xc7, 0xf5, 0x44, 0x36, 0x7c, 0x62, 0x1c, 0x9b, 0xb2, 0xb2, 0x80, 0x9e},
          {0x13, 0x70, 0x4d, 0x44, 0x8a, 0x26, 0x8f, 0x32, 0x76, 0x7c, 0x7f, 0x47, 0xb1, 0x89, 0x3b, 0x71},
          {0xd9, 0x80, 0xbf, 0x53, 0x6b, 0x32, 0x3f, 0xcd, 0x78, 0x42, 0x72, 0x89, 0xf2, 0x64, 0xfd, 0xbb},
          {0x84, 0x18, 0x82, 0xfc, 0x35, 0x91, 0xb9, 0x8d, 0x5c, 0xd6, 0xe2, 0xc5, 0x37, 0xe4, 0xdd, 0x08},
          {0x4f, 0xa6, 0xaf, 0x81, 0xbd, 0xc2, 0x52, 0x3a, 0x39, 0xda, 0xd0, 0xc6, 0x0c, 0x4b, 0x69, 0x4b},
          {0xe7, 0x2f, 0x51, 0x3b, 0xd0, 0xcb, 0x8c, 0x33, 0x9f, 0x6d, 0x23, 0xb2, 0x22, 0xaf, 0x71, 0x88},
          {0x1b, 0x75, 0xa1, 0x4e, 0x17, 0x3e, 0xc8, 0x05, 0x45, 0xc7, 0x3a, 0xcb, 0x95, 0x0c, 0xb6, 0xf8},
          {0x0a, 0x61, 0x95, 0x4a, 0x28, 0xce, 0xe4, 0xc2, 0x33, 0xbb, 0x45, 0x8c, 0x24, 0x85, 0x8d, 0x89},
          {0xf2, 0x9a, 0x9d, 0xfd, 0x67, 0x96, 0x2b, 0x05, 0x6d, 0xf7, 0xbe, 0x4f, 0x45, 0x39, 0x5a, 0x8d},
          {0x76, 0x82, 0x1f, 0x01, 0x52, 0x07, 0x92, 0x88, 0x77, 0xd5, 0x59, 0xfd, 0x10, 0x43, 0x72, 0xf8},
          {0x7d, 0xb4, 0xcc, 0xb7, 0x38, 0x8d, 0x96, 0x3a, 0x4e, 0x0f, 0x89, 0x3b, 0x1c, 0x08, 0x1b, 0xb3},
          {0xc7, 0x7a, 0x34, 0x61, 0xd7, 0x39, 0x46, 0x99, 0xaa, 0x8d, 0x8a, 0x2e, 0x92, 0x00, 0x1c, 0x14}
      },
      {
          {0xb7, 0xe9, 0xf3, 0xd1, 0xe2, 0xf9, 0x2f, 0x1a, 0x8f, 0x35, 0xc6, 0x2f, 0x5d, 0xce, 0x67, 0x7a},
          {0xb1, 0x9e, 0x49, 0xbd, 0x02, 0x70, 0xde, 0xe2, 0xe7, 0xf4, 0x6b, 0xa6, 0x05, 0x0d, 0x44, 0xbc},
          {0x8a, 0x38, 0x82, 0x93, 0xd7, 0xf6, 0xe5, 0xe9, 0x66, 0x68, 0xac, 0x54, 0x64, 0x18, 0x72, 0xb6},
          {0x48, 0xb4, 0x25, 0xe5, 0x4d, 0xb9, 0x61, 0x59, 0xc7, 0x81, 0xe3, 0xca, 0x10, 0x77, 0x06, 0x23},
          {0x76, 0x1f, 0xaa, 0x77, 0x12, 0x07, 0xd8, 0xc1, 0x89, 0xd5, 0x5d, 0x2c, 0xc4, 0x6c, 0x3c, 0x75},
          {0x03, 0xed, 0xdf, 0xbf, 0x13, 0x9a, 0xd9, 0x9c, 0x65, 0x85, 0x73, 0xeb, 0x77, 0x82, 0xab, 0x2a},
          {0x92, 0xb7, 0xb8, 0xd9, 0x56, 0xdb, 0x84, 0xac, 0x55, 0x36, 0x5b, 0x13, 0x46, 0xac, 0x82, 0x8f},
          {0x23, 0x29, 0xf1, 0x64, 0x54, 0xab, 0x5a, 0x4e, 0xe0, 0x09, 0x97, 0xf9, 0xb6, 0xd2, 0x13, 0x55},
          {0xe3, 0xe4, 0x48, 0x46, 0xa5, 0x48, 0xca, 0xc9, 0x86, 0x61, 0x3b, 0xad, 0xd2, 0xca, 0x61, 0xe3},
          {0xb4, 0xe6, 0x86, 0x4c, 0x02, 0x34, 0x95, 0x19, 0xe1, 0xd0, 0xdd, 0x5f, 0x44, 0x98, 0x17, 0x96},
          {0xc2, 0xf9, 0x2c, 0x3b, 0x10, 0x33, 0x4d, 0xd8, 0x37, 0x05, 0xe7, 0x86, 0x35, 0x31, 0x72, 0x9f},
          {0xd4, 0xe1, 0xaf, 0xc0, 0x90, 0x79, 0xb8, 0x56, 0x52, 0x80, 0x94, 0x6d, 0x42, 0xb3, 0xd9, 0xb5},
          {0xda, 0x30, 0x32, 0xaa, 0xef, 0x01, 0x40, 0x35, 0x3b, 0xe0, 0xef, 0xf5, 0xab, 0x99, 0x57, 0xa3}
      },
      {
          {0xa9, 0x57, 0x19, 0x06, 0x6e, 0x71, 0xf5, 0x26, 0x0b, 0x1c, 0x30, 0xc0, 0xa4, 0xe9, 0x0d, 0xf7},
          {0x3d, 0xdc, 0xce, 0x29, 0x56, 0x45, 0xd5, 0x3e, 0xc6, 0x54, 0xab, 0xb7, 0xa8, 0x25, 0x5e, 0x91},
          {0xa3, 0x39, 0x6e, 0x51, 0x07, 0xd0, 0x63, 0xa6, 0x3a, 0x0c, 0xad, 0x8f, 0x6c, 0x49, 0x78, 0xb1},
          {0xff, 0xe8, 0x63, 0xe7, 0x57, 0xcd, 0x3d, 0x76, 0xf4, 0xf4, 0x53, 0x27, 0xf3, 0x24, 0x30, 0x81},
          {0xc9, 0x28, 0x9d, 0x0e, 0xa5, 0x61, 0xe5, 0xbf, 0x14, 0x31, 0x6b, 0xe1, 0x43, 0xfc, 0x56, 0x97},
          {0xb7, 0x08, 0x05, 0xb0, 0x44, 0x2c, 0x35, 0x31, 0x8d, 0x04, 0xa8, 0x3f, 0x28, 0x65, 0x4d, 0x80},
          {0x51, 0xd2, 0xa6, 0xd5, 0x12, 0x2e, 0xf0, 0x42, 0xa5, 0x26, 0xf5, 0xf2, 0xe1, 0x0a, 0xc0, 0xc3},
          {0x6c, 0x0e, 0x68, 0xfc, 0x44, 0x6b, 0x25, 0x7c, 0x3e, 0xed, 0xb6, 0xce, 0x2c, 0xc3, 0x46, 0x8c},
          {0x89, 0xe5, 0xb3, 0x7e, 0x68, 0xef, 0x73, 0xbd, 0x04, 0xe1, 0x1b, 0x41, 0x40, 0x8a, 0x3e, 0x3d},
          {0x60, 0x5f, 0x91, 0xc7, 0x4c, 0x9c, 0xd7, 0x4b, 0xc5, 0x79, 0x64, 0x35, 0xad, 0x96, 0x17, 0x88},
          {0xa9, 0x77, 0x0c, 0xc9, 0xe9, 0xfd, 0x32, 0xf4, 0x74, 0x7c, 0x2e, 0xd9, 0x38, 0xe0, 0xf9, 0x92},
          {0xfd, 0x99, 0x9d, 0xa7, 0x50, 0x0f, 0x8a, 0x2f, 0xf9, 0x78, 0x86, 0xe6, 0x10, 0x85, 0xb4, 0x12},
          {0x63, 0xf1, 0xe7, 0x13, 0x5b, 0x11, 0x1e, 0x81, 0xa6, 0x88, 0x83, 0x26, 0xf6, 0x87, 0x09, 0x09}
      }
  };
  uint8_t result[13][16] = {};
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES192 Rijndael Key Expansion test... "
              << std::flush;
    HCL::Crypto::RijndaelKeySchedule::AES192KeyExpansion(test_keys[i], result);
    if (CompareRoundKeys<13>(result, expected_round_keys[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowRoundKeyError<24, 13>(test_keys[i], expected_round_keys[i], result);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES256KeyExpansionTest() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][32] = {
      {
          0x3c, 0x4c, 0xf5, 0x5e, 0xbc, 0xe7, 0x83, 0xb7, 0x6b, 0x89, 0xa3, 0xac, 0x1b, 0x23, 0xb8, 0x62,
          0x46, 0x79, 0x30, 0x37, 0xc8, 0x95, 0x3c, 0x90, 0x72, 0x0e, 0x9b, 0x41, 0xfc, 0xd4, 0x80, 0x77
      },
      {
          0x8d, 0xa9, 0xa3, 0x91, 0xe1, 0xca, 0x87, 0x7b, 0xa2, 0xe9, 0x6e, 0xac, 0x35, 0x22, 0x9d, 0x19,
          0xf6, 0x28, 0xe1, 0xdd, 0x1d, 0x9e, 0xc4, 0x3a, 0x3f, 0xdf, 0x99, 0x36, 0xd6, 0xf2, 0x13, 0x98
      },
      {
          0xa7, 0x4c, 0xae, 0xa1, 0xec, 0x29, 0xf9, 0x68, 0xb3, 0xef, 0xf7, 0x08, 0xba, 0x78, 0x49, 0x48,
          0x4b, 0x66, 0x2c, 0x1f, 0x6c, 0x1f, 0x5f, 0xe9, 0xb7, 0xda, 0x84, 0xa1, 0x30, 0x9a, 0x77, 0x56
      }
  };
  const uint8_t expected_round_keys[][15][16] = {
      {
          {0x3c, 0x4c, 0xf5, 0x5e, 0xbc, 0xe7, 0x83, 0xb7, 0x6b, 0x89, 0xa3, 0xac, 0x1b, 0x23, 0xb8, 0x62},
          {0x46, 0x79, 0x30, 0x37, 0xc8, 0x95, 0x3c, 0x90, 0x72, 0x0e, 0x9b, 0x41, 0xfc, 0xd4, 0x80, 0x77},
          {0x75, 0x81, 0x00, 0xee, 0xc9, 0x66, 0x83, 0x59, 0xa2, 0xef, 0x20, 0xf5, 0xb9, 0xcc, 0x98, 0x97},
          {0x10, 0x32, 0x76, 0xbf, 0xd8, 0xa7, 0x4a, 0x2f, 0xaa, 0xa9, 0xd1, 0x6e, 0x56, 0x7d, 0x51, 0x19},
          {0x88, 0x50, 0xd4, 0x5f, 0x41, 0x36, 0x57, 0x06, 0xe3, 0xd9, 0x77, 0xf3, 0x5a, 0x15, 0xef, 0x64},
          {0xae, 0x6b, 0xa9, 0xfc, 0x76, 0xcc, 0xe3, 0xd3, 0xdc, 0x65, 0x32, 0xbd, 0x8a, 0x18, 0x63, 0xa4},
          {0x21, 0xab, 0x9d, 0x21, 0x60, 0x9d, 0xca, 0x27, 0x83, 0x44, 0xbd, 0xd4, 0xd9, 0x51, 0x52, 0xb0},
          {0x9b, 0xba, 0xa9, 0x1b, 0xed, 0x76, 0x4a, 0xc8, 0x31, 0x13, 0x78, 0x75, 0xbb, 0x0b, 0x1b, 0xd1},
          {0x02, 0x04, 0xa3, 0xcb, 0x62, 0x99, 0x69, 0xec, 0xe1, 0xdd, 0xd4, 0x38, 0x38, 0x8c, 0x86, 0x88},
          {0x9c, 0xde, 0xed, 0xdf, 0x71, 0xa8, 0xa7, 0x17, 0x40, 0xbb, 0xdf, 0x62, 0xfb, 0xb0, 0xc4, 0xb3},
          {0xf5, 0x18, 0xce, 0xc4, 0x97, 0x81, 0xa7, 0x28, 0x76, 0x5c, 0x73, 0x10, 0x4e, 0xd0, 0xf5, 0x98},
          {0xb3, 0xae, 0x0b, 0x99, 0xc2, 0x06, 0xac, 0x8e, 0x82, 0xbd, 0x73, 0xec, 0x79, 0x0d, 0xb7, 0x5f},
          {0x02, 0xb1, 0x01, 0x72, 0x95, 0x30, 0xa6, 0x5a, 0xe3, 0x6c, 0xd5, 0x4a, 0xad, 0xbc, 0x20, 0xd2},
          {0x26, 0xcb, 0xbc, 0x2c, 0xe4, 0xcd, 0x10, 0xa2, 0x66, 0x70, 0x63, 0x4e, 0x1f, 0x7d, 0xd4, 0x11},
          {0xbd, 0xf9, 0x83, 0xb2, 0x28, 0xc9, 0x25, 0xe8, 0xcb, 0xa5, 0xf0, 0xa2, 0x66, 0x19, 0xd0, 0x70}
      },
      {
          {0x8d, 0xa9, 0xa3, 0x91, 0xe1, 0xca, 0x87, 0x7b, 0xa2, 0xe9, 0x6e, 0xac, 0x35, 0x22, 0x9d, 0x19},
          {0xf6, 0x28, 0xe1, 0xdd, 0x1d, 0x9e, 0xc4, 0x3a, 0x3f, 0xdf, 0x99, 0x36, 0xd6, 0xf2, 0x13, 0x98},
          {0x05, 0xd4, 0xe5, 0x67, 0xe4, 0x1e, 0x62, 0x1c, 0x46, 0xf7, 0x0c, 0xb0, 0x73, 0xd5, 0x91, 0xa9},
          {0x79, 0x2b, 0x60, 0x0e, 0x64, 0xb5, 0xa4, 0x34, 0x5b, 0x6a, 0x3d, 0x02, 0x8d, 0x98, 0x2e, 0x9a},
          {0x41, 0xe5, 0x5d, 0x3a, 0xa5, 0xfb, 0x3f, 0x26, 0xe3, 0x0c, 0x33, 0x96, 0x90, 0xd9, 0xa2, 0x3f},
          {0x19, 0x1e, 0x5a, 0x7b, 0x7d, 0xab, 0xfe, 0x4f, 0x26, 0xc1, 0xc3, 0x4d, 0xab, 0x59, 0xed, 0xd7},
          {0x8e, 0xb0, 0x53, 0x58, 0x2b, 0x4b, 0x6c, 0x7e, 0xc8, 0x47, 0x5f, 0xe8, 0x58, 0x9e, 0xfd, 0xd7},
          {0x73, 0x15, 0x0e, 0x75, 0x0e, 0xbe, 0xf0, 0x3a, 0x28, 0x7f, 0x33, 0x77, 0x83, 0x26, 0xde, 0xa0},
          {0x71, 0xad, 0xb3, 0xb4, 0x5a, 0xe6, 0xdf, 0xca, 0x92, 0xa1, 0x80, 0x22, 0xca, 0x3f, 0x7d, 0xf5},
          {0x07, 0x60, 0xf1, 0x93, 0x09, 0xde, 0x01, 0xa9, 0x21, 0xa1, 0x32, 0xde, 0xa2, 0x87, 0xec, 0x7e},
          {0x76, 0x63, 0x40, 0x8e, 0x2c, 0x85, 0x9f, 0x44, 0xbe, 0x24, 0x1f, 0x66, 0x74, 0x1b, 0x62, 0x93},
          {0x95, 0xcf, 0x5b, 0x4f, 0x9c, 0x11, 0x5a, 0xe6, 0xbd, 0xb0, 0x68, 0x38, 0x1f, 0x37, 0x84, 0x46},
          {0xcc, 0x3c, 0x1a, 0x4e, 0xe0, 0xb9, 0x85, 0x0a, 0x5e, 0x9d, 0x9a, 0x6c, 0x2a, 0x86, 0xf8, 0xff},
          {0x70, 0x8b, 0x1a, 0x59, 0xec, 0x9a, 0x40, 0xbf, 0x51, 0x2a, 0x28, 0x87, 0x4e, 0x1d, 0xac, 0xc1},
          {0x28, 0xad, 0x62, 0x61, 0xc8, 0x14, 0xe7, 0x6b, 0x96, 0x89, 0x7d, 0x07, 0xbc, 0x0f, 0x85, 0xf8}
      },
      {
          {0xa7, 0x4c, 0xae, 0xa1, 0xec, 0x29, 0xf9, 0x68, 0xb3, 0xef, 0xf7, 0x08, 0xba, 0x78, 0x49, 0x48},
          {0x4b, 0x66, 0x2c, 0x1f, 0x6c, 0x1f, 0x5f, 0xe9, 0xb7, 0xda, 0x84, 0xa1, 0x30, 0x9a, 0x77, 0x56},
          {0x1e, 0xb9, 0x1f, 0xa5, 0xf2, 0x90, 0xe6, 0xcd, 0x41, 0x7f, 0x11, 0xc5, 0xfb, 0x07, 0x58, 0x8d},
          {0x44, 0xa3, 0x46, 0x42, 0x28, 0xbc, 0x19, 0xab, 0x9f, 0x66, 0x9d, 0x0a, 0xaf, 0xfc, 0xea, 0x5c},
          {0xac, 0x3e, 0x55, 0xdc, 0x5e, 0xae, 0xb3, 0x11, 0x1f, 0xd1, 0xa2, 0xd4, 0xe4, 0xd6, 0xfa, 0x59},
          {0x2d, 0x55, 0x6b, 0x89, 0x05, 0xe9, 0x72, 0x22, 0x9a, 0x8f, 0xef, 0x28, 0x35, 0x73, 0x05, 0x74},
          {0x27, 0x55, 0xc7, 0x4a, 0x79, 0xfb, 0x74, 0x5b, 0x66, 0x2a, 0xd6, 0x8f, 0x82, 0xfc, 0x2c, 0xd6},
          {0x3e, 0xe5, 0x1a, 0x7f, 0x3b, 0x0c, 0x68, 0x5d, 0xa1, 0x83, 0x87, 0x75, 0x94, 0xf0, 0x82, 0x01},
          {0xa3, 0x46, 0xbb, 0x68, 0xda, 0xbd, 0xcf, 0x33, 0xbc, 0x97, 0x19, 0xbc, 0x3e, 0x6b, 0x35, 0x6a},
          {0x8c, 0x9a, 0x8c, 0x7d, 0xb7, 0x96, 0xe4, 0x20, 0x16, 0x15, 0x63, 0x55, 0x82, 0xe5, 0xe1, 0x54},
          {0x6a, 0xbe, 0x9b, 0x7b, 0xb0, 0x03, 0x54, 0x48, 0x0c, 0x94, 0x4d, 0xf4, 0x32, 0xff, 0x78, 0x9e},
          {0xaf, 0x8c, 0x30, 0x76, 0x18, 0x1a, 0xd4, 0x56, 0x0e, 0x0f, 0xb7, 0x03, 0x8c, 0xea, 0x56, 0x57},
          {0xcd, 0x0f, 0xc0, 0x1f, 0x7d, 0x0c, 0x94, 0x57, 0x71, 0x98, 0xd9, 0xa3, 0x43, 0x67, 0xa1, 0x3d},
          {0xb5, 0x09, 0x02, 0x51, 0xad, 0x13, 0xd6, 0x07, 0xa3, 0x1c, 0x61, 0x04, 0x2f, 0xf6, 0x37, 0x53},
          {0xcf, 0x95, 0x2d, 0x0a, 0xb2, 0x99, 0xb9, 0x5d, 0xc3, 0x01, 0x60, 0xfe, 0x80, 0x66, 0xc1, 0xc3}
      }
  };
  uint8_t result[15][16] = {};
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number << " of AES256 Rijndael Key Expansion test... "
              << std::flush;
    HCL::Crypto::RijndaelKeySchedule::AES256KeyExpansion(test_keys[i], result);
    if (CompareRoundKeys<15>(result, expected_round_keys[i]) != 0) {
      std::cerr << "Error:" << std::endl;
      ShowRoundKeyError<32, 15>(test_keys[i], expected_round_keys[i], result);
      return 1;
    } else {
      std::cout << "Success!" << std::endl;
    }
  }
  return 0;
}

static int AES128KeyExpansionPerformanceTest() {
  const size_t tests_number = 1000000;
  std::vector<std::array<uint8_t, 16>> keys;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
  uint8_t result[11][16];

  std::cout << "Generating " << tests_number << " random keys to run AES 128 Key Expansion performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    keys.emplace_back(std::array<uint8_t, 16>());
    for (uint8_t &byte : keys[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (auto &key : keys) {
    HCL::Crypto::RijndaelKeySchedule::AES128KeyExpansion(key.data(), result);
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 128 Key Expansions in " << duration << "us." << std::endl;
  return 0;
}

static int AES192KeyExpansionPerformanceTest() {
  const size_t tests_number = 1000000;
  std::vector<std::array<uint8_t, 24>> keys;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
  uint8_t result[13][16];

  std::cout << "Generating " << tests_number << " random keys to run AES 192 Key Expansion performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    keys.emplace_back(std::array<uint8_t, 24>());
    for (uint8_t &byte : keys[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (auto &key : keys) {
    HCL::Crypto::RijndaelKeySchedule::AES192KeyExpansion(key.data(), result);
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 192 Key Expansions in " << duration << "us." << std::endl;
  return 0;
}

static int AES256KeyExpansionPerformanceTest() {
  const size_t tests_number = 1000000;
  std::vector<std::array<uint8_t, 32>> keys;
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
  uint8_t result[15][16];

  std::cout << "Generating " << tests_number << " random keys to run AES 256 Key Expansion performance test... "
            << std::flush;
  for (int i = 0; i < tests_number; ++i) {
    keys.emplace_back(std::array<uint8_t, 32>());
    for (uint8_t &byte : keys[i]) {
      byte = dist_byte(rng);
    }
  }
  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
  auto t1 = std::chrono::high_resolution_clock::now();
  for (auto &key : keys) {
    HCL::Crypto::RijndaelKeySchedule::AES256KeyExpansion(key.data(), result);
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  std::cout << "Done! Computed " << tests_number << " AES 256 Key Expansions in " << duration << "us." << std::endl;
  return 0;
}

static int (*rijndael_key_schedule_test_functions[])() = {
    AES128KeyExpansionTest,
    AES192KeyExpansionTest,
    AES256KeyExpansionTest,
    AES128KeyExpansionPerformanceTest,
    AES192KeyExpansionPerformanceTest,
    AES256KeyExpansionPerformanceTest,
    nullptr
};

int RijndaelKeyScheduleTests() {
  for (int i = 0; rijndael_key_schedule_test_functions[i] != nullptr; ++i) {
    if (rijndael_key_schedule_test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
