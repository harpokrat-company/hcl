//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_RSA_PUBLIC_KEY_LINKAGE_H
#define HCL_RSA_PUBLIC_KEY_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Crypto/RSAKey.h"
#include "../services/Harpokrat/Secrets/PublicKey.h"

extern "C" {
const char *GetOwnerFromPublicKey(HCL::PublicKey *public_key);
void SetPublicKeyOwner(HCL::PublicKey *public_key, const char *owner);
std::string *EncryptMessageWithPublicKey(HCL::PublicKey *public_key, const char *message);
HCL::Crypto::RSAKey *ExtractKeyFromPublicKey(const HCL::PublicKey *private_key);
};

#endif //HCL_RSA_PUBLIC_KEY_LINKAGE_H
