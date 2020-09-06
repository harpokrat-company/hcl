//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() : r1(gmp_randinit_mt) {
  r1.seed(time(NULL));
}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) : r1(gmp_randinit_mt) {}

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

HCL::Crypto::KeyPair *HCL::Crypto::RSA::GenerateKeyPair(size_t bits) {
  if (!prime_generator_) {
    throw std::runtime_error(GetDependencyUnsetError("generate key pair", "Prime generator"));
  }
  mpz_class p = prime_generator_->GenerateRandomPrime(bits);
  mpz_class q = prime_generator_->GenerateRandomPrime(bits);
  mpz_class n = p * q;
  mpz_class phi_n = (p - 1) * (q - 1);
  mpz_class e = r1.get_z_range(phi_n);
  mpz_class d = 0;
  // Ensure that e and phi(n) are co-prime
  while (gcd(e, phi_n) != 1)
    e = r1.get_z_range(phi_n);
  mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi_n.get_mpz_t());
  return new KeyPair(e, d, n);
}

std::string HCL::Crypto::RSA::RSAEncrypt(const mpz_class &modulus, const mpz_class &public_key, const std::string &content) {
  mpz_t encrypted;
  mpz_class result;

  mpz_init(encrypted);
  // TODO PKCS1
//  mpz_powm(encrypted, content.get_mpz_t(), public_key.get_mpz_t(), modulus.get_mpz_t());
  result = mpz_class(encrypted);
  mpz_clear(encrypted);
  return "";
}

std::string HCL::Crypto::RSA::RSADecrypt(const mpz_class &modulus, const mpz_class &private_key, const std::string &content) {
  mpz_t decrypted;
  mpz_class result;

  mpz_init(decrypted);
  // TODO PKCS1
//  mpz_powm(decrypted, content.get_mpz_t(), private_key.get_mpz_t(), modulus.get_mpz_t());
  result = mpz_class(decrypted);
  mpz_clear(decrypted);
  return "";
}

std::string HCL::Crypto::RSA::Encrypt(const mpz_class &modulus, const mpz_class &public_key,
                                      const std::string &content) {
  return RSAEncrypt(modulus, public_key, content);
}

std::string HCL::Crypto::RSA::Decrypt(const mpz_class &modulus,
                                      const mpz_class &private_key,
                                      const std::string &content) {
  return RSADecrypt(modulus, private_key, content);
}
