//
// Created by neodar on 13/01/2020.
//

#ifndef HCL_SECRET_LINKAGE_H
#define HCL_SECRET_LINKAGE_H

#include <string>
#include "linkage.h"
#include "../services/Harpokrat/Secret.h"

extern "C" {
HCL::Secret *GetSecretFromContent(const char *key, const char *raw_content);
HCL::Secret *CreateSecret();
bool CorrectSecretDecryption(HCL::Secret *secret);
const char *GetNameFromSecret(HCL::Secret *secret);
const char *GetLoginFromSecret(HCL::Secret *secret);
const char *GetPasswordFromSecret(HCL::Secret *secret);
const char *GetDomainFromSecret(HCL::Secret *secret);
void UpdateSecretName(HCL::Secret *secret, const char *name);
void UpdateSecretLogin(HCL::Secret *secret, const char *login);
void UpdateSecretPassword(HCL::Secret *secret, const char *password);
void UpdateSecretDomain(HCL::Secret *secret, const char *domain);
std::string *GetContentStringFromSecret(HCL::Secret *secret, const char *key);
void DeleteSecret(HCL::Secret *secret);
};
#endif //HCL_SECRET_LINKAGE_H
