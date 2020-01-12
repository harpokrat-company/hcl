//
// Created by neodar on 12/01/2020.
//

#include "Base64.h"

const std::string HCL::Crypto::Base64::base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                      "abcdefghijklmnopqrstuvwxyz"
                                                      "0123456789+/";

// TODO Test
std::string HCL::Crypto::Base64::encode(std::string const &bytes) {
    std::string base64;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (const char& c : bytes) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for(i = 0; (i <4) ; i++) {
                base64 += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    if (i) {
        for(j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for (j = 0; (j < i + 1); j++) {
            base64 += base64_chars[char_array_4[j]];
        }
        while((i++ < 3)) {
            base64 += '=';
        }
    }

    return base64;
}
