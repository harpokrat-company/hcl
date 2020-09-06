//
// Created by neodar on 13/01/2020.
//

#include "secret.h"

extern "C" {
HCL::ASecret *EXPORT_FUNCTION DeserializeSecret(const char *key, const char *content) {
  return HCL::ASecret::DeserializeSecret(key, content);
}
}
