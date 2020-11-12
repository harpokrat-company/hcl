//
// Created by antoine on 28/08/2020.
//

#include "KeyPair.h"

#include <utility>

HCL::Crypto::KeyPair::KeyPair(__mpz_struct public_key, __mpz_struct private_key, __mpz_struct modulus) :
    modulus_(modulus),
    private_key_(private_key),
    public_key_(public_key) {
}

HCL::PublicKey *HCL::Crypto::KeyPair::GetPublic() const {
  return new HCL::PublicKey(modulus_, public_key_);
}

HCL::PrivateKey *HCL::Crypto::KeyPair::GetPrivate() const {
  return new HCL::PrivateKey(modulus_, private_key_);
}
