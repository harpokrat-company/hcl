//
// Created by neodar on 13/01/2020.
//

#include <iostream>
#include "secret.h"

extern "C" {
HCL::ASecret *EXPORT_FUNCTION DeserializeSecret(const char *key, const char *content) {
  return HCL::ASecret::DeserializeSecretExternal(key, content);
}

HCL::ASecret *EXPORT_FUNCTION DeserializeSecretAsymmetric(const HCL::Crypto::RSAKey *key, const char *content) {
  return HCL::ASecret::DeserializeSecretExternalAsymmetric(key, content);
}

std::string *EXPORT_FUNCTION SerializeSecret(HCL::ASecret *secret, const char *key) {
  return new std::string(secret->SerializeExternal(key));
}

std::string *EXPORT_FUNCTION SerializeSecretAsymmetric(HCL::ASecret *secret, const HCL::Crypto::RSAKey *key) {
  return new std::string(secret->SerializeExternalAsymmetric(key));
}

bool EXPORT_FUNCTION GetSecretCorrectDecryption(HCL::ASecret *secret) {
  return secret->CorrectDecryption();
}

void EXPORT_FUNCTION SecretInitializeAsymmetricCipher(HCL::ASecret *secret) {
  secret->InitializeAsymmetricCipher();
}

void EXPORT_FUNCTION SecretInitializeSymmetricCipher(HCL::ASecret *secret) {
  secret->InitializeSymmetricCipher();
}

std::string *EXPORT_FUNCTION GetSecretTypeName(HCL::ASecret *secret) {
  return new std::string(secret->GetSecretTypeName());
}

void EXPORT_FUNCTION DeleteSecret(HCL::ASecret *secret) {
  delete secret;
}
}
