//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_SECRET_LINKAGE_H
#define HCL_SECRET_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secrets/ASecret.h"
#include "../services/Crypto/Ciphers/ICipherDecryptionKey.h"
#include "../services/Crypto/Ciphers/ICipherEncryptionKey.h"

extern "C" {
HCL::ASecret *DeserializeSecret(const HCL::Crypto::ICipherDecryptionKey *key, const char *content);
std::string *SerializeSecret(HCL::ASecret *secret, const HCL::Crypto::ICipherEncryptionKey *key);
void SecretInitializeAsymmetricCipher(HCL::ASecret *secret);
void SecretInitializeSymmetricCipher(HCL::ASecret *secret);
bool GetSecretCorrectDecryption(HCL::ASecret *secret);
std::string *GetSecretTypeName(HCL::ASecret *secret);
void DeleteSecret(HCL::ASecret *secret);
};

#endif //HCL_SECRET_LINKAGE_H
