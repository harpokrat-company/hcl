#include "library.h"
#include "services/Crypto/Base64.h"

#include <memory.h>

char * AllocateRawString(const std::string &string) {
    return strdup(string.c_str());
}

extern "C" char *GetBasicAuth(const char *raw_email, const char *raw_password) {
    std::string email(raw_email);
    std::string password(raw_password); // TODO password derivation

    return AllocateRawString("Basic " + HCL::Crypto::Base64::encode(email + ":" + password));
}

extern "C" void ReleaseAllocatedMemory(void *pointer) {
    free(pointer);
}
