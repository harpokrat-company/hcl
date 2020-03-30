//
// Created by neodar on 28/03/2020.
//

#include "RijndaelKeySchedule.h"

const uint8_t HCL::Crypto::RijndaelKeySchedule::round_constants_[11] =
    {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

template<uint8_t KeySize, uint8_t RoundKeys>
void HCL::Crypto::RijndaelKeySchedule::KeyExpansion(const uint8_t key[KeySize],
                                                    uint8_t round_keys[RoundKeys][16]) {
  uint8_t temporary_word[4];

  for (int i = 0; i < KeySize; ++i) {
    round_keys[i / 16][i % 16] = key[i];
  }
  for (int i = KeySize / 4; i < RoundKeys * 4; ++i) {
    HCL::Crypto::CryptoHelper::CopyWord(WORD_AT(round_keys, i - 1), temporary_word);
    if (i % (KeySize / 4) == 0) {
      HCL::Crypto::CryptoHelper::RotWord(temporary_word, temporary_word);
      RijndaelSubstitutionBox::SubWord(temporary_word, temporary_word);
      temporary_word[0] ^= round_constants_[i / (KeySize / 4)];
    } else if (KeySize > 24 && i % (KeySize / 4) == 4) {
      RijndaelSubstitutionBox::SubWord(temporary_word, temporary_word);
    }
    HCL::Crypto::CryptoHelper::XorWords(WORD_AT(round_keys, i - (KeySize / 4)), temporary_word, WORD_AT(round_keys, i));
  }
}

void HCL::Crypto::RijndaelKeySchedule::AES128KeyExpansion(const uint8_t key[16], uint8_t round_keys[11][16]) {
  KeyExpansion<16, 11>(key, round_keys);
}

void HCL::Crypto::RijndaelKeySchedule::AES192KeyExpansion(const uint8_t key[24], uint8_t round_keys[13][16]) {
  KeyExpansion<24, 13>(key, round_keys);
}

void HCL::Crypto::RijndaelKeySchedule::AES256KeyExpansion(const uint8_t key[32], uint8_t round_keys[15][16]) {
  KeyExpansion<32, 15>(key, round_keys);
}
