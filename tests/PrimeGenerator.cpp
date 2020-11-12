//
// Created by antoine on 27/06/2020.
//

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/PrimeGenerators/APrimeGenerator.h"

static int CustomPrimeGenerator() {
  auto pgenerator = HCL::Crypto::Factory<HCL::Crypto::APrimeGenerator>::BuildTypedFromName("custom-prime-generator");
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
  __mpz_struct result;
  std::cout << "Running prime numbers generator tests..." << std::endl;
  for (size_t i = 0; i < 10; ++i) {
    std::cout << test_bits[i] << " bits: " << std::flush;
    result = pgenerator->GenerateRandomPrime(test_bits[i]);
    std::cout << (mpz_probab_prime_p(&result, 10) > 0 ? "OK :)" : "KO >:(") << std::endl;
    mpz_clear(&result);
  }
  return 0;
}

static int (*prime_generator_test_functions[])() = {
	CustomPrimeGenerator,
	nullptr
};

int PrimeGeneratorTests() {
  for (int i = 0; prime_generator_test_functions[i] != nullptr; ++i) {
	if (prime_generator_test_functions[i]() != 0) {
	  return 1;
	}
  }
  return 0;
}