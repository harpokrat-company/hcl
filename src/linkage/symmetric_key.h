//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_SYMMETRIC_KEY_LINKAGE_H
#define HCL_SYMMETRIC_KEY_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secrets/SymmetricKey.h"

extern "C" {
HCL::SymmetricKey *CreateSymmetricKey();
const char *GetOwnerFromSymmetricKey(HCL::SymmetricKey *symmetric_key);
void SetSymmetricKeyOwner(HCL::SymmetricKey *symmetric_key, const char *owner);
const char *GetKeyFromSymmetricKey(HCL::SymmetricKey *symmetric_key);
const char *GetSymmetricKeyEncryptionKeyType(HCL::SymmetricKey *symmetric_key);
void SetSymmetricKeyKey(HCL::SymmetricKey *symmetric_key, const char *key);
};

#endif //HCL_SYMMETRIC_KEY_LINKAGE_H
