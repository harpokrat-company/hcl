//
// Created by neodar on 30/03/2020.
//

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>

#include "../src/services/Crypto/BlockCiphers/Rijndael.h"
#include "../src/services/Crypto/HashFunctions/AHashFunction.h"
#include "../src/services/Crypto/Factory.h"

static int SHA256Test() {
  const std::array<std::string, 4> test_data = {
      "",
      "a",
      "Aled oskour",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In venenatis lectus quis cursus suscipit. Curabitur vitae varius turpis. Nunc vitae quam et justo placerat tempus. Nunc vestibulum ante eu risus elementum mattis. Suspendisse in varius elit, in consectetur ante. Ut vestibulum diam nec urna iaculis, dignissim elementum magna consectetur. Integer dapibus sem ullamcorper, ullamcorper nisl non, tempus risus. Sed nec congue justo. Nullam enim lorem, posuere id ipsum eget, scelerisque congue enim. Phasellus vel nulla libero. Aliquam libero quam, tincidunt eu feugiat quis, dictum et ipsum. Nulla pellentesque sagittis lectus, eu euismod massa vulputate id."
  };
  const std::array<std::string, 4> expected_hashes = {
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "f4732ffd0084c702f7ffd3136ccc1c2cc4d45dbffb32c41138e3034fb840c299",
      "26fc8520f6e70b602e4c33bc70f7147bcf3af208e2d570563e83fef6b52ed0cd"
  };
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::BuildTypedFromName("sha256");
  for (size_t i = 0; i < test_data.size(); i++) {
    std::cout << "Running test data " << i + 1 << "/" << test_data.size() << " of SHA256 hash function test... "
              << std::flush;
    std::string hash = sha512->HashData(test_data[i]);
    std::stringstream hex_hash;
    for (auto c : hash) {
      hex_hash << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_hash.str() == expected_hashes[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_hashes[i] << std::endl;
      std::cout << "But got:\t" << hex_hash.str() << std::endl;
    }
  }
  return 0;
}

static int SHA512Test() {
  const std::array<std::string, 4> test_data = {
      "",
      "a",
      "Aled oskour",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In venenatis lectus quis cursus suscipit. Curabitur vitae varius turpis. Nunc vitae quam et justo placerat tempus. Nunc vestibulum ante eu risus elementum mattis. Suspendisse in varius elit, in consectetur ante. Ut vestibulum diam nec urna iaculis, dignissim elementum magna consectetur. Integer dapibus sem ullamcorper, ullamcorper nisl non, tempus risus. Sed nec congue justo. Nullam enim lorem, posuere id ipsum eget, scelerisque congue enim. Phasellus vel nulla libero. Aliquam libero quam, tincidunt eu feugiat quis, dictum et ipsum. Nulla pellentesque sagittis lectus, eu euismod massa vulputate id."
  };
  const std::array<std::string, 4> expected_hashes = {
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
      "243b35d727502f1d70046e78179a8a271c3decaae5768ffe6c3841a0be46eceb1594f054aa91f9a694a2ebac2fa93d09f3043c5bc7f3ea000874bec0310a1813",
      "1c9cacf68068bebf5b7202ed43a6ab59a6ba0a7cb6b201d48a5e6c4615b52ec1048f49dafd0e92f3b66d26dab24485794a6b7dffc55c6d1f347570d69406bc46"
  };
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::BuildTypedFromName("sha512");
  for (size_t i = 0; i < test_data.size(); i++) {
    std::cout << "Running test data " << i + 1 << "/" << test_data.size() << " of SHA512 hash function test... "
              << std::flush;
    std::string hash = sha512->HashData(test_data[i]);
    std::stringstream hex_hash;
    for (auto c : hash) {
      hex_hash << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
    }
    if (hex_hash.str() == expected_hashes[i]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Error :(" << std::endl;
      std::cout << "Expected:\t" << expected_hashes[i] << std::endl;
      std::cout << "But got:\t" << hex_hash.str() << std::endl;
    }
  }
  return 0;
}

static int (*sha_test_functions[])() = {
    SHA256Test,
    SHA512Test,
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
