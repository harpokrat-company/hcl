//
// Created by antoine on 28/08/2020.
//

#include "KeyPair.h"

#include <utility>

HCL::Crypto::KeyPair::KeyPair(mpz_class public_key, mpz_class private_key, mpz_class modulus) :
    modulus_(std::move(modulus)),
    private_key_(std::move(private_key)),
    public_key_(std::move(public_key)) {
}

HCL::PublicKey HCL::Crypto::KeyPair::GetPublic() const {
  return HCL::PublicKey(modulus_, public_key_);
}

HCL::PrivateKey HCL::Crypto::KeyPair::GetPrivate() const {
  return HCL::PrivateKey(modulus_, private_key_);
}
