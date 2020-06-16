//
// Created by neodar on 30/03/2020.
//

#include <string>
#include <iomanip>
#include <iostream>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/SuperFactory.h"
#include "../src/services/Crypto/Ciphers/ACipher.h"
#include "../src/services/Crypto/EncryptedBlob.h"
#include "../src/services/Harpokrat/Secret.h"

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

  std::cout << "Running test of full workflow (CBC(PKCS7/AES256(PBKDF2(MT19937/HMAC(SHA256)))/MT19937))... "
            << std::flush;
  hmac->SetDependency(std::move(sha256), 0);
  pbkdf2->SetDependency(std::move(hmac), 0);
  pbkdf2->SetDependency(std::move(mt19927_pbkdf), 1);
  aes256->SetDependency(std::move(pbkdf2), 0);
  cbc->SetDependency(std::move(aes256), 0);
  cbc->SetDependency(std::move(pkcs7), 1);
  cbc->SetDependency(std::move(mt19927_cbc), 2);
  cipher->SetDependency(std::move(cbc), 0);

  HCL::Crypto::EncryptedBlob origin;
  origin.SetCipher(std::move(cipher));

  const std::string key = "Qwerty";
  const std::string message =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In venenatis lectus quis cursus suscipit. Curabitur vitae varius turpis.";

  origin.SetContent(message);

  std::string ciphered_message = origin.GetEncryptedContent(key);
  HCL::Crypto::EncryptedBlob destination(key, ciphered_message);
  std::string deciphered_message = destination.GetContent();
  if (message == deciphered_message) {
    std::cout << "Success!" << std::endl;
  } else {
    std::cout << "Error :(" << std::endl;
    std::cout << "Expected:\t" << message << std::endl;
    std::cout << "But got:\t" << deciphered_message << std::endl;
    std::cout << "But got (hex):" << std::endl << "---" << std::endl;
    PrintHex(deciphered_message);
    std::cout << "---" << std::endl;
  }
  return 0;
}

static int SecretTest() {
  const std::string key = "The answer to the life, the universe and everything...";

  std::cout << "Running test of autonomous Secret... "
            << std::flush;
  HCL::Secret origin_secret;

  origin_secret.SetName("Google");
  origin_secret.SetDomain("https://www.google.com/");
  origin_secret.SetLogin("neodar");
  origin_secret.SetPassword("qwerty123456789");

  HCL::Secret destination_secret(key, origin_secret.Serialize(key));
  return 0;
}

static int (*full_workflow_test_functions[])() = {
    DefaultFullEncryptionDecryptionTest,
    SecretTest,
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
