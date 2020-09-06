//
// Created by antoine on 27/06/2020.
//

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/PrimeGenerators/APrimeGenerator.h"
#include "../src/services/Crypto/AsymmetricCiphers/AAsymmetricCipher.h"
#include "../src/services/Crypto/AsymmetricCiphers/KeyPair.h"

static int SimpleRSATest() {
  auto pgenerator = HCL::Crypto::Factory<HCL::Crypto::APrimeGenerator>::BuildTypedFromName("custom-prime-generator");
  auto rsa = HCL::Crypto::Factory<HCL::Crypto::AAsymmetricCipher>::BuildTypedFromName("rsa");
  rsa->SetDependency(std::move(pgenerator), 0);
  static int test_bits[10] = {
	  8,
	  16,
	  32,
	  64,
	  128,
	  256,
	  512,
	  1024,
	  2048,
	  4096
  };
  mpz_class text, encrypted, decrypted;
  text = 12;
  std::cout << "Running RSA tests..." << std::endl;
  for (int test_bit : test_bits) {
	std::cout << "Generating " << test_bit << " bits keys: " << std::flush;
    HCL::Crypto::KeyPair *keys = rsa->GenerateKeyPair(test_bit);
	std::cout << "OK :)" << std::endl;
    std::cout << "Testing Encrypt/Decrypt integrity using " << test_bit << " bits keys: " << std::flush;
//    encrypted = encrypted = rsa->Encrypt(keys.GetPublic(), text);
//    encrypted = keys.GetPublic().Encrypt(text);
//    decrypted = rsa->Decrypt(keys.GetPrivate(), encrypted);
//    decrypted = keys.GetPrivate().Decrypt("");
    std::cout << (text == decrypted ? "OK :)" : "KO >:(") << std::endl;
  }
  return 0;
}

static int (*rsa_test_functions[])() = {
	SimpleRSATest,
	nullptr
};

int RSATests() {
  for (int i = 0; rsa_test_functions[i] != nullptr; ++i) {
	if (rsa_test_functions[i]() != 0) {
	  return 1;
	}
  }
  return 0;
}