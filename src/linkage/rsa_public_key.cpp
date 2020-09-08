//
// Created by neodar on 13/01/2020.
//

#include "rsa_public_key.h"

extern "C" {
const char *EXPORT_FUNCTION GetOwnerFromPublicKey(HCL::PublicKey *public_key) {
  return public_key->GetOwner().c_str();
}

void EXPORT_FUNCTION SetPublicKeyOwner(HCL::PublicKey *public_key, const char *owner) {
  public_key->SetOwner(owner);
}

std::string *EXPORT_FUNCTION EncryptMessageWithPublicKey(HCL::PublicKey *public_key, const char *message) {
  return new std::string(public_key->Encrypt(message));
}
}
