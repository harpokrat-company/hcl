//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() {}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) {}

std::string HCL::Crypto::RSA::GetHeader() {
  if (!prime_generator_) {
	throw std::runtime_error(GetDependencyUnsetError("get header", "Prime generator"));
  }
  return GetIdBytes() + prime_generator_->GetHeader();
}

void HCL::Crypto::RSA::SetPrimeGenerator(std::unique_ptr<ACryptoElement> hash_function) {
  prime_generator_ = ACryptoElement::UniqueTo<APrimeGenerator>(std::move(hash_function));
}

bool HCL::Crypto::RSA::IsPrimeGeneratorSet() const {
  return !!prime_generator_;
}

HCL::Crypto::ACryptoElement &HCL::Crypto::RSA::GetPrimeGenerator() const {
  if (!IsPrimeGeneratorSet()) {
	throw std::runtime_error(GetDependencyUnsetError("get Prime generator", "Prime generator"));
  }
  return *prime_generator_;
}

KeyPair HCL::Crypto::RSA::GenerateKeyPair(size_t bits) {
  //TODO ADD THE METHOD
  if (!prime_generator_) {
	throw std::runtime_error(GetDependencyUnsetError("generate key pair", "Prime generator"));
  }
  KeyPair keys = KeyPair(3, 7, 33);
  return keys;
}

mpz_class HCL::Crypto::RSA::Encrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content) {
  //The key should be a keyset containing the public key (n, e) (e l'exposant de chiffrement et n le module de chiffrement)
  // Should be removed (temporary)
  mpz_class e = key.second;
  mpz_class n = key.first;
  // -----------------
  mpz_t encrypted;
  mpz_class result;

  mpz_init(encrypted);
  mpz_powm(encrypted, content.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
  result = mpz_class (encrypted);
  mpz_clear(encrypted);
  return result;
}

mpz_class HCL::Crypto::RSA::Decrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content) {
  //The key should be a keyset containing the private key (n, d) (d l'exposant de déchiffrement et n le module de chiffrement)
  // Should be removed (temporary)
  mpz_class d = key.second;
  mpz_class n = key.first;
  // -----------------
  mpz_t decrypted;
  mpz_class result;

  mpz_init(decrypted);
  mpz_powm(decrypted, content.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
  result = mpz_class (decrypted);
  mpz_clear(decrypted);
  return result;
}