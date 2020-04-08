//
// Created by neodar on 30/03/2020.
//

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>

#include "../src/services/Crypto/BlockCiphers/Rijndael.h"
#include "../src/services/Crypto/Factory.h"

static int AES128EncryptTest() {
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
  const std::array<std::string, 3> expected_ciphered_data = {
      "8a5a0b7217a7c60a3ebbc859f2953844",
      "0b11d26405c3c978a32dceb26a803cfd",
      "04d483c3933f07e7f8f060a6a272d518"
  };
  auto aes128 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes128");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 128 block cipher encryption test... "
              << std::flush;
    std::string ciphered_data =
        aes128->EncryptBloc(std::string((char *) test_keys[i], 16), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_ciphered_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_ciphered_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

static int AES192EncryptTest() {
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
  const std::array<std::string, 3> expected_ciphered_data = {
      "545b7d91d6905710e779a3fe9d6e25ff",
      "e73bc2ffe97e92b332b530f59b0a9776",
      "7f5524fc02d0129f40eadfead147b19c"
  };
  auto aes192 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes192");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 192 block cipher encryption test... "
              << std::flush;
    std::string ciphered_data =
        aes192->EncryptBloc(std::string((char *) test_keys[i], 24), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_ciphered_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_ciphered_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

static int AES256EncryptTest() {
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
  const std::array<std::string, 3> expected_ciphered_data = {
      "4dc1bc18c1ea6a50e528d7a7f2593afb",
      "6d04ccd2c2a4861ed29c58174a4e74e2",
      "641a0b128d6bd3c94f5ff1302f90f16a"
  };
  auto aes256 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes256");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 256 block cipher encryption test... "
              << std::flush;
    std::string ciphered_data =
        aes256->EncryptBloc(std::string((char *) test_keys[i], 32), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_ciphered_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_ciphered_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

static int AES128DecryptTest() {
  const size_t tests_number = 3;
  const uint8_t test_keys[][16] = {
      {0xf6, 0x95, 0xb9, 0x7f, 0x88, 0xcd, 0x9a, 0xb0, 0x8c, 0x8c, 0x03, 0xb3, 0x84, 0xd6, 0x69, 0x84},
      {0x90, 0x8d, 0x44, 0x12, 0xef, 0xc1, 0xe7, 0x29, 0xf1, 0x04, 0xfc, 0x4f, 0x66, 0xae, 0xe6, 0x79},
      {0xd8, 0xee, 0xde, 0xe4, 0x8d, 0x68, 0x01, 0xac, 0xb7, 0xf0, 0x22, 0xe4, 0x5b, 0x1f, 0xe0, 0x24}
  };
  uint8_t test_data[][16] = {
      {0x8a, 0x5a, 0x0b, 0x72, 0x17, 0xa7, 0xc6, 0x0a, 0x3e, 0xbb, 0xc8, 0x59, 0xf2, 0x95, 0x38, 0x44},
      {0x0b, 0x11, 0xd2, 0x64, 0x05, 0xc3, 0xc9, 0x78, 0xa3, 0x2d, 0xce, 0xb2, 0x6a, 0x80, 0x3c, 0xfd},
      {0x04, 0xd4, 0x83, 0xc3, 0x93, 0x3f, 0x07, 0xe7, 0xf8, 0xf0, 0x60, 0xa6, 0xa2, 0x72, 0xd5, 0x18}
  };
  const std::array<std::string, 3> expected_plain_data = {
      "e8f29222dac9982938cd21ed3b043327",
      "5e7177b4de4850fc7492ddb9e3ee562a",
      "706c367347e96d63060f25ec0a4bc9a2"
  };
  auto aes128 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes128");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 128 block cipher decryption test... "
              << std::flush;
    std::string ciphered_data =
        aes128->DecryptBloc(std::string((char *) test_keys[i], 16), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_plain_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_plain_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

static int AES192DecryptTest() {
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
      {0x54, 0x5b, 0x7d, 0x91, 0xd6, 0x90, 0x57, 0x10, 0xe7, 0x79, 0xa3, 0xfe, 0x9d, 0x6e, 0x25, 0xff},
      {0xe7, 0x3b, 0xc2, 0xff, 0xe9, 0x7e, 0x92, 0xb3, 0x32, 0xb5, 0x30, 0xf5, 0x9b, 0x0a, 0x97, 0x76},
      {0x7f, 0x55, 0x24, 0xfc, 0x02, 0xd0, 0x12, 0x9f, 0x40, 0xea, 0xdf, 0xea, 0xd1, 0x47, 0xb1, 0x9c}
  };
  const std::array<std::string, 3> expected_plain_data = {
      "8f40980043c7dbb44afd1688cd293e41",
      "994405e25e58f890e13a5da1f1ec487b",
      "cb3aa132b41ed0e5b06fb5375a0b97c6"
  };
  auto aes192 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes192");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 192 block cipher decryption test... "
              << std::flush;
    std::string ciphered_data =
        aes192->DecryptBloc(std::string((char *) test_keys[i], 24), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_plain_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_plain_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

static int AES256DecryptTest() {
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
      {0x4d, 0xc1, 0xbc, 0x18, 0xc1, 0xea, 0x6a, 0x50, 0xe5, 0x28, 0xd7, 0xa7, 0xf2, 0x59, 0x3a, 0xfb},
      {0x6d, 0x04, 0xcc, 0xd2, 0xc2, 0xa4, 0x86, 0x1e, 0xd2, 0x9c, 0x58, 0x17, 0x4a, 0x4e, 0x74, 0xe2},
      {0x64, 0x1a, 0x0b, 0x12, 0x8d, 0x6b, 0xd3, 0xc9, 0x4f, 0x5f, 0xf1, 0x30, 0x2f, 0x90, 0xf1, 0x6a}
  };
  const std::array<std::string, 3> expected_plain_data = {
      "f3e484063e3c4e388bd54365131fb277",
      "b5e5c191a96daa319ba7d860fc865d9d",
      "ae91b09c3ba79545176b1c8ce7f3990e"
  };
  auto aes256 = HCL::Crypto::Factory<HCL::Crypto::ABlockCipher>::BuildTypedFromName("aes256");
  for (int i = 0; i < tests_number; ++i) {
    std::cout << "Running test data " << i + 1 << "/" << tests_number
              << " of Rijndael AES 256 block cipher decryption test... "
              << std::flush;
    std::string ciphered_data =
        aes256->DecryptBloc(std::string((char *) test_keys[i], 32), std::string((char *) test_data[i], 16));
    std::stringstream hex_ciphered_data;
    for (auto c : ciphered_data) {
      hex_ciphered_data << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_ciphered_data.str() == expected_plain_data[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_plain_data[i] << std::endl;
      std::cout << "But got:\t" << hex_ciphered_data.str() << std::endl;
    }
  }
  return 0;
}

//static int AES128PerformanceTest() {
//  const size_t tests_number = 100000;
//  std::vector<std::array<uint8_t, 16>> test_keys;
//  std::vector<std::array<uint8_t, 16>> test_data;
//  std::random_device dev;
//  std::mt19937 rng(dev());
//  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
//
//  std::cout << "Generating " << tests_number
//            << " random keys and data block to run Rijndael 128 block cipher performance test... "
//            << std::flush;
//  for (int i = 0; i < tests_number; ++i) {
//    test_keys.emplace_back(std::array<uint8_t, 16>());
//    test_data.emplace_back(std::array<uint8_t, 16>());
//    for (uint8_t &byte : test_keys[i]) {
//      byte = dist_byte(rng);
//    }
//    for (uint8_t &byte : test_data[i]) {
//      byte = dist_byte(rng);
//    }
//  }
//  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
//  auto t1 = std::chrono::high_resolution_clock::now();
//  for (int i = 0; i < tests_number; ++i) {
//    HCL::Crypto::Rijndael::AES128Encrypt(test_keys[i].data(), test_data[i].data());
//    HCL::Crypto::Rijndael::AES128Decrypt(test_keys[i].data(), test_data[i].data());
//  }
//  auto t2 = std::chrono::high_resolution_clock::now();
//  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
//  std::cout << "Done! Encrypted & decrypted " << tests_number << " Rijndael 128 block ciphers in " << duration << "us."
//            << std::endl;
//  return 0;
//}
//
//static int AES192PerformanceTest() {
//  const size_t tests_number = 100000;
//  std::vector<std::array<uint8_t, 24>> test_keys;
//  std::vector<std::array<uint8_t, 16>> test_data;
//  std::random_device dev;
//  std::mt19937 rng(dev());
//  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
//
//  std::cout << "Generating " << tests_number
//            << " random keys and data block to run Rijndael 192 block cipher performance test... "
//            << std::flush;
//  for (int i = 0; i < tests_number; ++i) {
//    test_keys.emplace_back(std::array<uint8_t, 24>());
//    test_data.emplace_back(std::array<uint8_t, 16>());
//    for (uint8_t &byte : test_keys[i]) {
//      byte = dist_byte(rng);
//    }
//    for (uint8_t &byte : test_data[i]) {
//      byte = dist_byte(rng);
//    }
//  }
//  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
//  auto t1 = std::chrono::high_resolution_clock::now();
//  for (int i = 0; i < tests_number; ++i) {
//    HCL::Crypto::Rijndael::AES192Encrypt(test_keys[i].data(), test_data[i].data());
//    HCL::Crypto::Rijndael::AES192Decrypt(test_keys[i].data(), test_data[i].data());
//  }
//  auto t2 = std::chrono::high_resolution_clock::now();
//  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
//  std::cout << "Done! Encrypted & decrypted " << tests_number << " Rijndael 192 block ciphers in " << duration << "us."
//            << std::endl;
//  return 0;
//}
//
//static int AES256PerformanceTest() {
//  const size_t tests_number = 100000;
//  std::vector<std::array<uint8_t, 32>> test_keys;
//  std::vector<std::array<uint8_t, 16>> test_data;
//  std::random_device dev;
//  std::mt19937 rng(dev());
//  std::uniform_int_distribution<std::mt19937::result_type> dist_byte(0, 255);
//
//  std::cout << "Generating " << tests_number
//            << " random keys and data block to run Rijndael 256 block cipher performance test... "
//            << std::flush;
//  for (int i = 0; i < tests_number; ++i) {
//    test_keys.emplace_back(std::array<uint8_t, 32>());
//    test_data.emplace_back(std::array<uint8_t, 16>());
//    for (uint8_t &byte : test_keys[i]) {
//      byte = dist_byte(rng);
//    }
//    for (uint8_t &byte : test_data[i]) {
//      byte = dist_byte(rng);
//    }
//  }
//  std::cout << "Done!" << std::endl << "Running test... " << std::flush;
//  auto t1 = std::chrono::high_resolution_clock::now();
//  for (int i = 0; i < tests_number; ++i) {
//    HCL::Crypto::Rijndael::AES256Encrypt(test_keys[i].data(), test_data[i].data());
//    HCL::Crypto::Rijndael::AES256Decrypt(test_keys[i].data(), test_data[i].data());
//  }
//  auto t2 = std::chrono::high_resolution_clock::now();
//  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
//  std::cout << "Done! Encrypted & decrypted " << tests_number << " Rijndael 256 block ciphers in " << duration << "us."
//            << std::endl;
//  return 0;
//}

static int (*aes_test_functions[])() = {
    AES128EncryptTest,
    AES192EncryptTest,
    AES256EncryptTest,
    AES128DecryptTest,
    AES192DecryptTest,
    AES256DecryptTest,
//    AES128PerformanceTest,
//    AES192PerformanceTest,
//    AES256PerformanceTest,
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
