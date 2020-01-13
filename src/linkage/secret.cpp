//
// Created by neodar on 13/01/2020.
//

#include "secret.h"

extern "C" {
    HCL::Secret *GetSecretFromContent(const char *raw_content) {
        return new HCL::Secret(raw_content);
    }

    const char *GetNameFromSecret(HCL::Secret *secret) {
        return secret->GetName().c_str();
    }

    const char *GetLoginFromSecret(HCL::Secret *secret) {
        return secret->GetLogin().c_str();
    }

    const char *GetPasswordFromSecret(HCL::Secret *secret) {
        return secret->GetPassword().c_str();
    }

    const char *GetDomainFromSecret(HCL::Secret *secret) {
        return secret->GetDomain().c_str();
    }

    void UpdateSecretName(HCL::Secret *secret, const char *name) {
        secret->SetName(name);
    }

    void UpdateSecretLogin(HCL::Secret *secret, const char *login) {
        secret->SetLogin(login);
    }

    void UpdateSecretPassword(HCL::Secret *secret, const char *password) {
        secret->SetPassword(password);
    }

    void UpdateSecretDomain(HCL::Secret *secret, const char *domain) {
        secret->SetDomain(domain);
    }

    std::string *GetContentStringFromSecret(HCL::Secret *secret) {
        return new std::string(secret->Serialize());
    }

    void DeleteSecret(HCL::Secret *secret) {
        delete secret;
    }
}
