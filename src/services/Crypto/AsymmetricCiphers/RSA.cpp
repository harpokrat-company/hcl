//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() {}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) {}

std::string HCL::Crypto::RSA::GetHeader() {
  return GetIdBytes();
}

mpz_class HCL::Crypto::RSA::Encrypt(const mpz_class &key, const mpz_class &content) {
  //The key should be a keyset containing the public key (e, n) (e l'exposant de chiffrement et n le module de chiffrement)
  // Should be removed (temporary)
  mpz_class e = 3;
  mpz_class n = 33;
  // -----------------
  mpz_t encrypted;
  mpz_class result;

  mpz_init(encrypted);
  mpz_powm(encrypted, content.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
  result = mpz_class (encrypted);
  mpz_clear(encrypted);
  return result;
}

mpz_class HCL::Crypto::RSA::Decrypt(const mpz_class &key, const mpz_class &content) {
  //The key should be a keyset containing the private key (d, n) (d l'exposant de déchiffrement et n le module de chiffrement)
  // Should be removed (temporary)
  mpz_class d = 7;
  mpz_class n = 33;
  // -----------------
  mpz_t decrypted;
  mpz_class result;

  mpz_init(decrypted);
  mpz_powm(decrypted, content.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
  result = mpz_class (decrypted);
  mpz_clear(decrypted);
  return result;
}