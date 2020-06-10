//
// Created by antoine on 10/06/2020.
//

#include "Fermat.h"

HCL::Crypto::Fermat::Fermat() {
}

HCL::Crypto::Fermat::Fermat(const std::string &header, size_t &header_length) : Fermat() {}

bool HCL::Crypto::Fermat::IsPrime(size_t number) {
  //TODO: Implement Algorithm
  return true;
}

std::string HCL::Crypto::Fermat::GetHeader() {
  return GetIdBytes();
}