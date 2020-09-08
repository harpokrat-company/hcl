//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_RSA_KEYPAIR_LINKAGE_H
#define HCL_RSA_KEYPAIR_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Crypto/AsymmetricCiphers/RSA.h"

extern "C" {
HCL::Crypto::KeyPair *GenerateRSAKeyPair(size_t bits);
HCL::PublicKey *GetPublicKeyFromRSAKeyPair(HCL::Crypto::KeyPair *key_pair);
HCL::PrivateKey *GetPrivateKeyFromRSAKeyPair(HCL::Crypto::KeyPair *key_pair);
void DeleteRSAKeyPair(HCL::Crypto::KeyPair *key_pair);
};

#endif //HCL_RSA_KEYPAIR_LINKAGE_H
