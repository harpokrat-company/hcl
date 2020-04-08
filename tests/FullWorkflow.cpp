//
// Created by neodar on 30/03/2020.
//

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/SuperFactory.h"
#include "../src/services/Crypto/Ciphers/ACipher.h"

static void PrintHex(const std::string &data) {
  std::stringstream hex_data_stream;
  std::string hex_data;

  for (auto c : data) {
    hex_data_stream << std::hex << std::setfill('0') << std::setw(2) << (int) (uint8_t) c;
  }
  hex_data = hex_data_stream.str();
  for (size_t i = 0; i < hex_data.length(); i += 32) {
    std::cout << hex_data.substr(i, 32) << std::endl;
  }
}
static int DefaultFullEncryptionDecryptionTest() {
  // Workflow of test:
  //
  // BlocCipherScheme (ACipher)
  // -> CBC (ABlocCipherMode)
  //    -> PKCS7 (APadding)
  //    -> AES256 (ABlocCipher)
  //       -> PBKDF2 (AKeyStretchingFunction)
  //          -> MT19937 (ARandomGenerator)
  //          -> HMAC (AMessageAuthenticationCode)
  //             -> SHA256 (AHashFunction)
  //    -> MT19937 (ARandomGenerator)
  //

  auto sha256 = HCL::Crypto::SuperFactory::GetFactoryOfType("hash-function").BuildFromName("sha256");
  auto hmac = HCL::Crypto::SuperFactory::GetFactoryOfType("message-authentication-code").BuildFromName("hmac");
  auto mt19927_pbkdf = HCL::Crypto::SuperFactory::GetFactoryOfType("random-generator").BuildFromName("mt19937");
  auto mt19927_cbc = HCL::Crypto::SuperFactory::GetFactoryOfType("random-generator").BuildFromName("mt19937");
  auto pbkdf2 = HCL::Crypto::SuperFactory::GetFactoryOfType("key-stretching-function").BuildFromName("pbkdf2");
  auto aes256 = HCL::Crypto::SuperFactory::GetFactoryOfType("block-cipher").BuildFromName("aes256");
  auto pkcs7 = HCL::Crypto::SuperFactory::GetFactoryOfType("padding").BuildFromName("pkcs7");
  auto cbc = HCL::Crypto::SuperFactory::GetFactoryOfType("block-cipher-mode").BuildFromName("cbc");
  auto cipher = HCL::Crypto::Factory<HCL::Crypto::ACipher>::BuildTypedFromName("block-cipher-scheme");

  hmac->SetDependency(std::move(sha256), 0);
  pbkdf2->SetDependency(std::move(hmac), 0);
  pbkdf2->SetDependency(std::move(mt19927_pbkdf), 1);
  aes256->SetDependency(std::move(pbkdf2), 0);
  cbc->SetDependency(std::move(aes256), 0);
  cbc->SetDependency(std::move(pkcs7), 1);
  cbc->SetDependency(std::move(mt19927_cbc), 2);
  cipher->SetDependency(std::move(cbc), 0);

  const std::string key = "Qwerty";
  const std::string message = "Hello world !";
  std::string ciphered_message = cipher->Encrypt(key, message);
  PrintHex(ciphered_message);
  std::cout << "---" << std::endl;
  PrintHex(cipher->GetHeader());
  std::cout << "---" << std::endl;
  std::cout << cipher->Decrypt(key, ciphered_message) << std::endl;
  return 0;
}

static int (*full_workflow_test_functions[])() = {
    DefaultFullEncryptionDecryptionTest,
    nullptr
};

int FullWorkflowTests() {
  for (int i = 0; full_workflow_test_functions[i] != nullptr; ++i) {
    if (full_workflow_test_functions[i]() != 0) {
      return 1;
    }
  }
  return 0;
}
