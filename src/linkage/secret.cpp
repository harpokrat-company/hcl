//
// Created by neodar on 13/01/2020.
//

#include <iostream>
#include "secret.h"

extern "C" {
HCL::ASecret *EXPORT_FUNCTION DeserializeSecret(const HCL::Crypto::ICipherDecryptionKey *key, const char *content) {
  return HCL::ASecret::DeserializeSecret(key, content);
}

std::string *EXPORT_FUNCTION SerializeSecret(HCL::ASecret *secret, const HCL::Crypto::ICipherEncryptionKey *key) {
  return new std::string(secret->Serialize(key));
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
