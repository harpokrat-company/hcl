//
// Created by neodar on 13/01/2020.
//

#include "secret.h"

extern "C" {
HCL::Secret *EXPORT_FUNCTION GetSecretFromContent(const char *raw_content) {
    return new HCL::Secret(raw_content);
}

HCL::Secret *EXPORT_FUNCTION CreateSecret() {
    return new HCL::Secret();
}

const char *EXPORT_FUNCTION GetNameFromSecret(HCL::Secret *secret) {
    return secret->GetName().c_str();
}

const char *EXPORT_FUNCTION GetLoginFromSecret(HCL::Secret *secret) {
    return secret->GetLogin().c_str();
}

const char *EXPORT_FUNCTION GetPasswordFromSecret(HCL::Secret *secret) {
    return secret->GetPassword().c_str();
}

const char *EXPORT_FUNCTION GetDomainFromSecret(HCL::Secret *secret) {
    return secret->GetDomain().c_str();
}

void EXPORT_FUNCTION UpdateSecretName(HCL::Secret *secret, const char *name) {
    secret->SetName(name);
}

void EXPORT_FUNCTION UpdateSecretLogin(HCL::Secret *secret, const char *login) {
    secret->SetLogin(login);
}

void EXPORT_FUNCTION UpdateSecretPassword(HCL::Secret *secret, const char *password) {
    secret->SetPassword(password);
}

void EXPORT_FUNCTION UpdateSecretDomain(HCL::Secret *secret, const char *domain) {
    secret->SetDomain(domain);
}

std::string *EXPORT_FUNCTION GetContentStringFromSecret(HCL::Secret *secret) {
    return new std::string(secret->Serialize());
}

void EXPORT_FUNCTION DeleteSecret(HCL::Secret *secret) {
    delete secret;
}
}
