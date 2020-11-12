//
// Created by antoine on 20/07/2020.
//

#include "RSA.h"

HCL::Crypto::RSA::RSA() {
  gmp_randinit_default(r1);
  gmp_randseed_ui(r1, time(nullptr));
}

HCL::Crypto::RSA::RSA(const std::string &header, size_t &header_length) {
  gmp_randinit_default(r1);
  gmp_randseed_ui(r1, time(nullptr));
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
  __mpz_struct n, phi_n, e, d, tmp, one;
  if (!prime_generator_) {
    throw std::runtime_error(GetDependencyUnsetError("generate key pair", "Prime generator"));
  }
  mpz_init(&n);
  mpz_init(&phi_n);
  mpz_init(&e);
  mpz_init(&d);
  mpz_init(&tmp);
  mpz_init(&one);
  mpz_set_ui(&one, 1);
  __mpz_struct p = prime_generator_->GenerateRandomPrime(bits / 2);
  __mpz_struct q = prime_generator_->GenerateRandomPrime(bits / 2);
  mpz_mul(&n, &p, &q); // n = p * q
  mpz_sub(&p, &p, &one); // p = p - 1
  mpz_sub(&q, &q, &one); // q = q -1
  mpz_mul(&phi_n, &p, &q); // phi_n = p * q
  mpz_urandomm (&e, r1, &phi_n); // e = a random integer between 0 and phi_n - 1
  // Ensure that e and phi(n) are co-prime
  mpz_gcd(&tmp, &e, &phi_n);
  while (mpz_cmp(&tmp, &one) != 0) {
    mpz_urandomm (&e, r1, &phi_n);
    mpz_gcd(&tmp, &e, &phi_n);
  }
  mpz_invert(&d, &e, &phi_n);
  mpz_clear(&phi_n);
  mpz_clear(&one);
  mpz_clear(&tmp);
  mpz_clear(&p);
  mpz_clear(&q);
  return new KeyPair(e, d, n);
}

std::string HCL::Crypto::RSA::RSAEncrypt(const __mpz_struct modulus, const __mpz_struct public_key, const std::string &content) {
  unsigned int block_size = (modulus._mp_size * (sizeof(mp_limb_t) * 8)) / 8;
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
    mpz_powm(c, m, &public_key, &modulus);
    mpz_export(mess_block, nullptr, 1, sizeof(char), 0, 0, c);
    result += std::string(mess_block, block_size);
  }
  return result;
}

std::string HCL::Crypto::RSA::RSADecrypt(const __mpz_struct modulus, const __mpz_struct private_key, const std::string &content) {
  unsigned int block_size = (modulus._mp_size * (sizeof(mp_limb_t) * 8)) / 8;
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
    mpz_powm(m, c, &private_key, &modulus);
    mpz_export(buff + 1, nullptr, 1, sizeof(char), 0, 0, m);
    for(it = 2; ((buff[it] != 0) && (it < block_size)); it++);
    it++;
    result += std::string(buff + it, block_size - it);
  }
  return result;
}

std::string HCL::Crypto::RSA::Encrypt(const __mpz_struct modulus, const __mpz_struct public_key,
                                      const std::string &content) {
  return RSAEncrypt(modulus, public_key, content);
}

std::string HCL::Crypto::RSA::Decrypt(const __mpz_struct modulus,
                                      const __mpz_struct private_key,
                                      const std::string &content) {
  return RSADecrypt(modulus, private_key, content);
}
