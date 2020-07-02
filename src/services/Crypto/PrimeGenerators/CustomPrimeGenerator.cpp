//
// Created by antoine on 27/06/2020.
//

#include <gmpxx.h>
#include <gmp.h>
#include "CustomPrimeGenerator.h"

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator() {
}

HCL::Crypto::CustomPrimeGenerator::CustomPrimeGenerator(const std::string &header, size_t &header_length) : CustomPrimeGenerator() {}

std::string HCL::Crypto::CustomPrimeGenerator::GetHeader() {
  return GetIdBytes();
}

static unsigned long get_seed() {
  return time(NULL);
}

//Source: https://tspiteri.gitlab.io/gmp-mpfr-sys/gmp/C_002b_002b-Class-Interface.html#C_002b_002b-Interface-Random-Numbers
mpz_class HCL::Crypto::CustomPrimeGenerator::GenerateRandomPrime(size_t bits) {
  mpz_class output;
  gmp_randclass r1(gmp_randinit_default);

  r1.seed(get_seed());
  output = r1.get_z_bits(bits);
  mpz_nextprime(output.get_mpz_t(), output.get_mpz_t());
  return output;
}


