//
// Created by neodar on 05/11/2020.
//

#include "RSAKey.h"

HCL::Crypto::RSAKey::RSAKey(mpz_class modulus, mpz_class key) {
  modulus_ = std::move(modulus);
  key_ = std::move(key);
}

mpz_class HCL::Crypto::RSAKey::GetModulus() const {
  return modulus_;
}

mpz_class HCL::Crypto::RSAKey::GetKey() const {
  return key_;
}
