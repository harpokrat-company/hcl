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
  std::string text;
  std::string hex("0123456789ABCDEF");
  char *ciphered;
  mpz_t m, res;

  for (unsigned int i = 0, j = 0; j < content.length(); i += 2, j++) {
    text.push_back(hex[content[j] / 16]);
    text.push_back(hex[content[j] % 16]);
  }
  mpz_inits(m, res, nullptr);
  mpz_set_str(m, text.c_str(), 16);
  mpz_powm(res, m, public_key.get_mpz_t(), modulus.get_mpz_t());
  ciphered = mpz_get_str(nullptr, 62, res);
  return std::string(ciphered);
}

std::string HCL::Crypto::RSA::RSADecrypt(const mpz_class &modulus, const mpz_class &private_key, const std::string &content) {
  mpz_t m, out;
  char *msg;
  char *message;
  unsigned int msg_len;

  mpz_inits(m, out, nullptr);
  mpz_set_str(m, content.c_str(), 62);
  mpz_powm_sec(out, m, private_key.get_mpz_t(), modulus.get_mpz_t());
  message = mpz_get_str(NULL, 16, out);
  msg_len = strlen(message);
  msg = (char*) malloc(sizeof(char) * (msg_len / 2 + 1));
  for (unsigned int i = 0, j = 0; i < msg_len; i += 2, j++)
	msg[j] = CHARS_TO_INT(message[i], message[i+1]);
  msg[msg_len / 2] = '\0';
  return std::string(msg);
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
