//
// Created by antoine on 27/06/2020.
//

#include <gmpxx.h>
#include <gmp.h>
#include "CustomPrimeGenerator.h"

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator() {
  gmp_randinit_default(r1);
  gmp_randseed_ui(r1, time(nullptr));
}

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator(const std::string &header, size_t &header_length) : CustomPrimeGenerator() {}

std::string HCL::Crypto::CustomPrimeGenerator::GetHeader() {
  return GetIdBytes();
}

//Source: https://tspiteri.gitlab.io/gmp-mpfr-sys/gmp/C_002b_002b-Class-Interface.html#C_002b_002b-Interface-Random-Numbers
__mpz_struct HCL::Crypto::CustomPrimeGenerator::GenerateRandomPrime(size_t bits) {
  __mpz_struct output;

  mpz_init(&output);
  mpz_urandomb(&output, r1, bits);
  mpz_nextprime(&output, &output);
  return output;
}
