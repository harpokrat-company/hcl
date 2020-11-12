//
// Created by neodar on 05/11/2020.
//

#include "RSAKey.h"

HCL::Crypto::RSAKey::RSAKey(__mpz_struct modulus, __mpz_struct key) {
  modulus_ = std::move(modulus);
  key_ = std::move(key);
}

__mpz_struct HCL::Crypto::RSAKey::GetModulus() const {
  return modulus_;
}

__mpz_struct HCL::Crypto::RSAKey::GetKey() const {
  return key_;
}
