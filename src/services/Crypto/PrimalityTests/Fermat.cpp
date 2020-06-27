//
// Created by antoine on 10/06/2020.
//

#include "Fermat.h"

HCL::Crypto::Fermat::Fermat() {
}

HCL::Crypto::Fermat::Fermat(const std::string &header, size_t &header_length) : Fermat() {}

bool HCL::Crypto::Fermat::IsPrime(BigNumber number) {
  BigNumber random;

  random = 2;
  return random.ModularExponentiation(number - 1, number) == 1;
}

std::string HCL::Crypto::Fermat::GetHeader() {
  return GetIdBytes();
}