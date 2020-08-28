//
// Created by antoine on 28/08/2020.
//

#include "KeyPair.h"

HCL::Crypto::KeyPair::KeyPair(const mpz_class &public_key, const mpz_class &private_key, const mpz_class &modulus) {
  this->public_key = std::pair(modulus, public_key);
  this->private_key = std::pair(modulus, private_key);
}

const std::pair<mpz_class,mpz_class>& HCL::Crypto::KeyPair::GetPrivate() {
  return this->private_key;
}

const std::pair<mpz_class, mpz_class>& HCL::Crypto::KeyPair::GetPublic() {
  return this->public_key;
}