//
// Created by neodar on 13/01/2020.
//

#include "rsa_private_key.h"

extern "C" {
const char *EXPORT_FUNCTION GetOwnerFromPrivateKey(HCL::PrivateKey *private_key) {
  return private_key->GetOwner().c_str();
}

void EXPORT_FUNCTION SetPrivateKeyOwner(HCL::PrivateKey *private_key, const char *owner) {
  private_key->SetOwner(owner);
}

std::string *EXPORT_FUNCTION DecryptMessageWithPrivateKey(HCL::PrivateKey *private_key, const char *message) {
  return new std::string(private_key->Decrypt(message));
}
}
