//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() : r1(gmp_randinit_mt) {}

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

static unsigned long get_seed() {
  return time(NULL);
}

HCL::Crypto::KeyPair HCL::Crypto::RSA::GenerateKeyPair(size_t bits) {
  if (!prime_generator_) {
	throw std::runtime_error(GetDependencyUnsetError("generate key pair", "Prime generator"));
  }
  if (!key_seeded) {
	r1.seed(get_seed());
	key_seeded = true;
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
  return KeyPair(e, d, n);
}

mpz_class HCL::Crypto::RSA::Encrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content) {
  mpz_t encrypted;
  mpz_class result;

  mpz_init(encrypted);
  mpz_powm(encrypted, content.get_mpz_t(), key.second.get_mpz_t(), key.first.get_mpz_t());
  result = mpz_class (encrypted);
  mpz_clear(encrypted);
  return result;
}

mpz_class HCL::Crypto::RSA::Decrypt(const std::pair<mpz_class, mpz_class> &key, const mpz_class &content) {
  mpz_t decrypted;
  mpz_class result;

  mpz_init(decrypted);
  mpz_powm(decrypted, content.get_mpz_t(), key.second.get_mpz_t(), key.first.get_mpz_t());
  result = mpz_class (decrypted);
  mpz_clear(decrypted);
  return result;
}