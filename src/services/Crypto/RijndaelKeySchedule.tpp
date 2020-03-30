//
// Created by neodar on 28/03/2020.
//

#include "RijndaelKeySchedule.h"

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
