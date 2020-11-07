//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() : r1(gmp_randinit_mt) {
  r1.seed(time(NULL));
}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) : r1(gmp_randinit_mt) {
  this->prime_generator_ = Factory<APrimeGenerator>::BuildTypedFromHeader(header, header_length);
}

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
  mpz_class p = prime_generator_->GenerateRandomPrime(bits / 2);
  mpz_class q = prime_generator_->GenerateRandomPrime(bits / 2);
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
  unsigned int block_size = (modulus.get_mpz_t()->_mp_size * (sizeof(mp_limb_t) * 8)) / 8;
  char mess_block[block_size];
  unsigned int prog = content.length();
  unsigned int processed_len = 0;
  unsigned int offset = 0;
  unsigned int it;
  std::string result;
  mpz_t m;
  mpz_t c;
  mpz_init(m);
  mpz_init(c);

  while (prog > 0) {
    processed_len = (prog >= (block_size - 11)) ? block_size - 11 : prog;
    it = 0;
    mess_block[it++] = 0x00;
    mess_block[it++] = 0x02;
    while(it < (block_size - processed_len - 1)) {
      mess_block[it++] = (rand() % (0xFF - 1)) + 1;
    }
    mess_block[it++] = 0x00;
    while (it < block_size) {
      mess_block[it++] = content[offset];
      offset++;
    }
    prog -= processed_len;
    mpz_import(m, block_size, 1, sizeof(char), 0, 0, mess_block);
    mpz_powm(c, m, public_key.get_mpz_t(), modulus.get_mpz_t());
    mpz_export(mess_block, nullptr, 1, sizeof(char), 0, 0, c);
    result += std::string(mess_block, block_size);
  }
  return result;
}

std::string HCL::Crypto::RSA::RSADecrypt(const mpz_class &modulus, const mpz_class &private_key, const std::string &content) {
  unsigned int block_size = (modulus.get_mpz_t()->_mp_size * (sizeof(mp_limb_t) * 8)) / 8;
  char buff[block_size];
  unsigned int nb_block = content.length() / block_size;
  const char *message = content.c_str();
  std::string result;
  unsigned int it;
  mpz_t c;
  mpz_t m;

  mpz_init(c);
  mpz_init(m);
  buff[0] = 0;
  for (int i = 0; i < nb_block; i++) {
    memset(buff, 0, block_size);
    mpz_import(c, block_size, 1, sizeof(char), 0, 0, message + i * block_size);
    mpz_powm(m, c, private_key.get_mpz_t(), modulus.get_mpz_t());
    mpz_export(buff + 1, nullptr, 1, sizeof(char), 0, 0, m);
    for(it = 2; ((buff[it] != 0) && (it < block_size)); it++);
    it++;
    result += std::string(buff + it, block_size - it);
  }
  return result;
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
