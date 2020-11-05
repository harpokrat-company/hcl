//
// Created by neodar on 05/11/2020.
//

#include "emscripten_binding.h"
#include "../services/Crypto/Base64.h"
#include "../services/Crypto/Factory.h"
#include "../services/Crypto/HashFunctions/AHashFunction.h"

HCL::Crypto::KeyPair *GenerateRSAKeyPair(size_t bits) {
  auto prime_generator =
      HCL::Crypto::Factory<HCL::Crypto::APrimeGenerator>::BuildTypedFromName("custom-prime-generator");
  auto rsa = HCL::Crypto::Factory<HCL::Crypto::AAsymmetricCipher>::BuildTypedFromName("rsa");
  rsa->SetDependency(std::move(prime_generator), 0);

  return rsa->GenerateKeyPair(bits);
}

std::string GetDerivedKey(const std::string &raw_password) {
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::BuildTypedFromName("sha512");

  return HCL::Crypto::Base64::Encode(sha512->HashData(raw_password));
}

std::string GetBasicAuthString(const std::string &email, const std::string &raw_password) {
  auto sha512 = HCL::Crypto::Factory<HCL::Crypto::AHashFunction>::BuildTypedFromName("sha512");
  std::string password(HCL::Crypto::Base64::Encode(sha512->HashData(raw_password)));

  // TODO Clean format with signature ?
  return "Basic " + HCL::Crypto::Base64::Encode(email + ":" + password);
}

std::string GetExceptionMessage(intptr_t exception) {
  return reinterpret_cast<std::exception *>(exception)->what();
}

HCL::Password *CastSecretToPassword(HCL::ASecret *secret) {
  return dynamic_cast<HCL::Password *>(secret);
}

HCL::PrivateKey *CastSecretToPrivateKey(HCL::ASecret *secret) {
  return dynamic_cast<HCL::PrivateKey *>(secret);
}

HCL::PublicKey *CastSecretToPublicKey(HCL::ASecret *secret) {
  return dynamic_cast<HCL::PublicKey *>(secret);
}

HCL::SymmetricKey *CastSecretToSymmetricKey(HCL::ASecret *secret) {
  return dynamic_cast<HCL::SymmetricKey *>(secret);
}
