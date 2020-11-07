//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_RSA_KEY_LINKAGE_H
#define HCL_RSA_KEY_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Crypto/RSAKey.h"

extern "C" {
void DeleteRSAKey(HCL::Crypto::RSAKey *key);
};

#endif //HCL_RSA_KEY_LINKAGE_H
