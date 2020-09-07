//
// Created by neodar on 13/01/2020.
//

#include "rsa_symmetric_key.h"

extern "C" {
HCL::SymmetricKey *EXPORT_FUNCTION CreateSymmetricKey() {
  return new HCL::SymmetricKey();
}

const char *EXPORT_FUNCTION GetOwnerFromSymmetricKey(HCL::SymmetricKey *symmetric_key) {
  return symmetric_key->GetOwner().c_str();
}

void EXPORT_FUNCTION SetSymmetricKeyOwner(HCL::SymmetricKey *symmetric_key, const char *owner) {
  symmetric_key->SetOwner(owner);
}

const char *EXPORT_FUNCTION GetKeyFromSymmetricKey(HCL::SymmetricKey *symmetric_key) {
  return symmetric_key->GetKey().c_str();
}

void EXPORT_FUNCTION SetSymmetricKeyKey(HCL::SymmetricKey *symmetric_key, const char *key) {
  symmetric_key->SetKey(key);
}
}
