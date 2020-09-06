//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_RSA_PRIVATE_KEY_LINKAGE_H
#define HCL_RSA_PRIVATE_KEY_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secrets/PrivateKey.h"

extern "C" {
const char *GetOwnerFromPrivateKey(HCL::PrivateKey *private_key);
void SetPrivateKeyOwner(HCL::PrivateKey *private_key, const char *owner);
std::string *DecryptMessageWithPrivateKey(HCL::PrivateKey *private_key, const char *message);
};

#endif //HCL_RSA_PRIVATE_KEY_LINKAGE_H
