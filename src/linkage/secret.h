//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_SECRET_LINKAGE_H
#define HCL_SECRET_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secrets/ASecret.h"

extern "C" {
HCL::ASecret *DeserializeSecret(const char *key, const char *content);
};

#endif //HCL_SECRET_LINKAGE_H
