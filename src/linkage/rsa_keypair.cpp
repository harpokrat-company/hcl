//
// Created by neodar on 13/01/2020.
//

#include "rsa_keypair.h"

extern "C" {
HCL::Crypto::KeyPair *EXPORT_FUNCTION GenerateRSAKeyPair(size_t bits) {
  auto prime_generator = HCL::Crypto::Factory<HCL::Crypto::APrimeGenerator>::BuildTypedFromName("custom-prime-generator");
  auto rsa = HCL::Crypto::Factory<HCL::Crypto::AAsymmetricCipher>::BuildTypedFromName("rsa");
  rsa->SetDependency(std::move(prime_generator), 0);

  return rsa->GenerateKeyPair(bits);
}

HCL::PublicKey *EXPORT_FUNCTION GetPublicKeyFromRSAKeyPair(HCL::Crypto::KeyPair *key_pair) {
  return key_pair->GetPublic();
}

HCL::PrivateKey *EXPORT_FUNCTION GetPrivateKeyFromRSAKeyPair(HCL::Crypto::KeyPair *key_pair) {
  return key_pair->GetPrivate();
}
}
