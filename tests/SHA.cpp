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

#include "../src/services/Crypto/BlockCiphers/Rijndael.h"
#include "../src/services/Crypto/HashFunctions/AHashFunction.h"
#include "../src/services/Crypto/Factory.h"

static int SHA256Test() {
  const char sha256_identifier[2] = {0x00, 0x01};
  const std::array<std::string, 3> test_data = {
      "",
      "Aled oskour",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In venenatis lectus quis cursus suscipit. Curabitur vitae varius turpis. Nunc vitae quam et justo placerat tempus. Nunc vestibulum ante eu risus elementum mattis. Suspendisse in varius elit, in consectetur ante. Ut vestibulum diam nec urna iaculis, dignissim elementum magna consectetur. Integer dapibus sem ullamcorper, ullamcorper nisl non, tempus risus. Sed nec congue justo. Nullam enim lorem, posuere id ipsum eget, scelerisque congue enim. Phasellus vel nulla libero. Aliquam libero quam, tincidunt eu feugiat quis, dictum et ipsum. Nulla pellentesque sagittis lectus, eu euismod massa vulputate id."
  };
  const std::array<std::string, 3> expected_hashes = {
      "",
      "",
      ""
  };
  size_t header_length = 0;
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::GetInstanceFromHeader(
      std::string(sha256_identifier, 2),
      header_length
  );
  for (size_t i = 0; i < test_data.size(); i++) {
    std::cout << "Running test data " << i + 1 << "/" << test_data.size() << " of SHA256 hash function test... "
              << std::flush;
    std::string hash = sha512->HashData(test_data[i]);
    if (hash == expected_hashes[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cerr << "Error :(" << std::endl;
      std::cerr << "Expected: ";
      for (auto c : expected_hashes[i]) {
        std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) c;
      }
      std::cerr << std::endl << "But got: ";
      for (auto c : hash) {
        std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) c;
      }
    }
  }
  return 0;
}

static int (*sha_test_functions[])() = {
    SHA256Test,
    nullptr
};

int SHATests() {
  for (int i = 0; sha_test_functions[i] != nullptr; ++i) {
    if (sha_test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
