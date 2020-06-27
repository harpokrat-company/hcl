//
// Created by antoine on 27/06/2020.
//

#include <iostream>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/PrimeGenerators/APrimeGenerator.h"
#include "../src/services/Crypto/BigNumber.h"

static int CustomPrimeGenerator() {

  auto pgenerator = HCL::Crypto::Factory<HCL::Crypto::APrimeGenerator>::BuildTypedFromName("custom-prime-generator");
  std::cout << "Running prime numbers generator tests" << std::endl;
  auto fermat = HCL::Crypto::SuperFactory::GetFactoryOfType("primality-test").BuildFromName("fermat");
  auto mt19937 = HCL::Crypto::SuperFactory::GetFactoryOfType("random-generator").BuildFromName("mt19937");
//  pgenerator->SetDependency(fermat, 1);
//  pgenerator->SetDependency(mt19937, 0);
//  pgenerator->GenerateRandomPrimeBigNumber(1);
  return 0;
}

static int (*prime_generator_test_functions[])() = {
	//CustomPrimeGenerator,
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