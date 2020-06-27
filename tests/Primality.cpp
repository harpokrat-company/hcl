//
// Created by antoine on 27/06/2020.
//

#include <iostream>

#include "../src/services/Crypto/Factory.h"
#include "../src/services/Crypto/PrimalityTests/APrimalityTest.h"
#include "../src/services/Crypto/BigNumber.h"

static int FermatTests() {
  std::map<std::string, bool> fermat_numbers = {
	  {"6", false},
	  {"5", true},
	  {"21", false},
	  {"1233", false},
	  {"35742549198872617291353508656626642567", true},
	  {"14693679385278593849609206715278070972733319459651094018859396328480215743184089660644531", true}
  };
  auto fermat = HCL::Crypto::Factory<HCL::Crypto::APrimalityTest>::BuildTypedFromName("fermat");
  std::cout << "Running primality test using Fermat primality test" << std::endl << std::flush;
  for (auto it = fermat_numbers.begin(); it != fermat_numbers.end(); it++) {
    std::cout << it->first << (it->second ? " (prime): " : " (not prime): ") << std::flush;
    if (fermat->IsPrime(HCL::Crypto::BigNumber(it->first, "0123456789")) != it->second)
      std::cout << "Failed" << std::endl;
    else
      std::cout << "Success" << std::endl;
  }
  return 0;
}

static int (*primality_test_functions[])() = {
	FermatTests,
	nullptr
};

int PrimalityTests() {
  for (int i = 0; primality_test_functions[i] != nullptr; ++i) {
	if (primality_test_functions[i]() != 0) {
	  return 1;
	}
  }
  return 0;
}