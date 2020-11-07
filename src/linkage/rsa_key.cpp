//
// Created by neodar on 13/01/2020.
//

#include "rsa_public_key.h"

extern "C" {
void DeleteRSAKey(HCL::Crypto::RSAKey *key) {
  delete key;
}
}
