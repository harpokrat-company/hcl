//
// Created by neodar on 05/11/2020.
//

#ifndef HCL_SRC_LINKAGE_EMSCRIPTEN_BINDING_H_
#define HCL_SRC_LINKAGE_EMSCRIPTEN_BINDING_H_

#include "../services/Crypto/AsymmetricCiphers/RSA.h"
#include "../services/Harpokrat/Secrets/ASecret.h"
#include "../services/Harpokrat/Secrets/Password.h"
#include "../services/Harpokrat/Secrets/PrivateKey.h"
#include "../services/Harpokrat/Secrets/PublicKey.h"
#include "../services/Harpokrat/Secrets/SymmetricKey.h"
#include "../services/Harpokrat/User.h"
#include "emscripten/bind.h"

HCL::Crypto::KeyPair *GenerateRSAKeyPair(size_t);
std::string GetDerivedKey(const std::string &);
std::string GetBasicAuthString(const std::string &, const std::string &);
std::string GetExceptionMessage(intptr_t);
HCL::Password *CastSecretToPassword(HCL::ASecret *);
HCL::PrivateKey *CastSecretToPrivateKey(HCL::ASecret *);
HCL::PublicKey *CastSecretToPublicKey(HCL::ASecret *);
HCL::SymmetricKey *CastSecretToSymmetricKey(HCL::ASecret *);


EMSCRIPTEN_BINDINGS(hcl) {
  emscripten::function("GenerateRSAKeyPair", &GenerateRSAKeyPair, emscripten::allow_raw_pointers());
  emscripten::function("GetDerivedKey", &GetDerivedKey);
  emscripten::function("GetBasicAuthString", &GetBasicAuthString);
  emscripten::function("GetExceptionMessage", &GetExceptionMessage, emscripten::allow_raw_pointers());
  emscripten::function("CastSecretToPassword", &CastSecretToPassword, emscripten::allow_raw_pointers());
  emscripten::function("CastSecretToPrivateKey", &CastSecretToPrivateKey, emscripten::allow_raw_pointers());
  emscripten::function("CastSecretToPublicKey", &CastSecretToPublicKey, emscripten::allow_raw_pointers());
  emscripten::function("CastSecretToSymmetricKey", &CastSecretToSymmetricKey, emscripten::allow_raw_pointers());
  emscripten::class_<HCL::Crypto::RSAKey>("RSAKey");
  emscripten::class_<HCL::Crypto::KeyPair>("KeyPair")
      .function("GetPublic", &HCL::Crypto::KeyPair::GetPublic, emscripten::allow_raw_pointers())
      .function("GetPrivate", &HCL::Crypto::KeyPair::GetPrivate, emscripten::allow_raw_pointers());
  emscripten::class_<HCL::User>("User")
      .constructor<std::string, std::string, std::string, std::string>()
      .function("GetEmail", &HCL::User::GetEmail)
      .function("GetPassword", &HCL::User::GetPassword)
      .function("GetFistName", &HCL::User::GetFirstName)
      .function("GetLastName", &HCL::User::GetLastName)
      .function("SetEmail", &HCL::User::SetEmail)
      .function("SetPassword", &HCL::User::SetPassword)
      .function("SetFistName", &HCL::User::SetFirstName)
      .function("SetLastName", &HCL::User::SetLastName);
  emscripten::class_<HCL::ASecret>("Secret")
      .class_function("Deserialize", &HCL::ASecret::DeserializeSecretExternal, emscripten::allow_raw_pointers())
      .class_function("DeserializeAsymmetric", &HCL::ASecret::DeserializeSecretExternalAsymmetric, emscripten::allow_raw_pointers())
      .function("Serialize", &HCL::ASecret::SerializeExternal, emscripten::allow_raw_pointers())
      .function("SerializeAsymmetric", &HCL::ASecret::SerializeExternalAsymmetric, emscripten::allow_raw_pointers())
      .function("CorrectDecryption", &HCL::ASecret::CorrectDecryption)
      .function("InitializePlainCipher", &HCL::ASecret::InitializePlainCipher)
      .function("InitializeSymmetricCipher", &HCL::ASecret::InitializeSymmetricCipher)
      .function("InitializeAsymmetricCipher", &HCL::ASecret::InitializeAsymmetricCipher)
      .function("GetSecretTypeName", &HCL::ASecret::GetSecretTypeName);
  emscripten::class_<HCL::PrivateKey, emscripten::base<HCL::ASecret>>("PrivateKey")
      .function("GetOwner", &HCL::PrivateKey::GetOwner)
      .function("SetOwner", &HCL::PrivateKey::SetOwner)
      .function("ExtractKey", &HCL::PrivateKey::ExtractKey, emscripten::allow_raw_pointers());
  emscripten::class_<HCL::PublicKey, emscripten::base<HCL::ASecret>>("PublicKey")
      .function("GetOwner", &HCL::PublicKey::GetOwner)
      .function("SetOwner", &HCL::PublicKey::SetOwner)
      .function("ExtractKey", &HCL::PublicKey::ExtractKey, emscripten::allow_raw_pointers());
  emscripten::class_<HCL::SymmetricKey, emscripten::base<HCL::ASecret>>("SymmetricKey")
      .constructor()
      .function("GetOwner", &HCL::SymmetricKey::GetOwner)
      .function("GetKey", &HCL::SymmetricKey::GetKey)
      .function("SetOwner", &HCL::SymmetricKey::SetOwner)
      .function("SetKey", &HCL::SymmetricKey::SetKey);
  emscripten::class_<HCL::Password, emscripten::base<HCL::ASecret>>("Password")
      .constructor()
      .function("GetName", &HCL::Password::GetName)
      .function("GetLogin", &HCL::Password::GetLogin)
      .function("GetPassword", &HCL::Password::GetPassword)
      .function("GetDomain", &HCL::Password::GetDomain)
      .function("SetName", &HCL::Password::SetName)
      .function("SetLogin", &HCL::Password::SetLogin)
      .function("SetPassword", &HCL::Password::SetPassword)
      .function("SetDomain", &HCL::Password::SetDomain);
}

#endif //HCL_SRC_LINKAGE_EMSCRIPTEN_BINDING_H_
