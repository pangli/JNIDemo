//
// Created by user on 2023/2/6.
//

#include <stdio.h>
#include "aes.h"
#include "aes_utils.h"
#include "hex_utils.h"
#include "base64_utils.h"
#include "junk.h"


#define BLOCKLEN 16


// key: uBdUx28vPAkDAb428d7NkjFoNcKWBuka
static const uint8_t *getKey() {
    _JUNK_FUN_0
    const int len = 32;
    uint8_t *src = malloc(len + 1);

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:
                src[i] = 'u';
                break;
            case 1:
                src[i] = 'B';
                break;
            case 2:
                src[i] = 'd';
                break;
            case 3:
                src[i] = 'U';
                _JUNK_FUN_1
                break;
            case 4:
                src[i] = 'x';
                break;
            case 5:
                src[i] = '2';
                break;
            case 6:
                src[i] = '8';
                break;
            case 7:
                src[i] = 'v';
                _JUNK_FUN_3
                break;
            case 8:
                src[i] = 'P';
                break;
            case 9:
                src[i] = 'A';
                break;
            case 10:
                src[i] = 'k';
                break;
            case 11:
                src[i] = 'D';
                _JUNK_FUN_2
                break;
            case 12:
                src[i] = 'A';
                break;
            case 13:
                src[i] = 'b';
                break;
            case 14:
                src[i] = '4';
                break;
            case 15:
                src[i] = '2';
                _JUNK_FUN_0
                break;
            case 16:
                src[i] = '8';
                break;
            case 17:
                src[i] = 'd';
                break;
            case 18:
                src[i] = '7';
                _JUNK_FUN_1
                break;
            case 19:
                src[i] = 'N';
                break;
            case 20:
                src[i] = 'k';
                break;
            case 21:
                src[i] = 'j';
                break;
            case 22:
                src[i] = 'F';
                _JUNK_FUN_2
                break;
            case 23:
                src[i] = 'o';
                break;
            case 24:
                src[i] = 'N';
                break;
            case 25:
                src[i] = 'c';
                _JUNK_FUN_3
                break;
            case 26:
                src[i] = 'K';
                break;
            case 27:
                src[i] = 'W';
                break;
            case 28:
                src[i] = 'B';
                break;
            case 29:
                src[i] = 'u';
                _JUNK_FUN_0
                break;
            case 30:
                src[i] = 'k';
                break;
            case 31:
                src[i] = 'a';
                break;

        }
    }
    src[len] = '\0';
    _JUNK_FUN_1
    return src;
}

// iv: c585Gq0YQA2QUlMc
static const uint8_t *getIV() {
    const int len = 16;
    _JUNK_FUN_2
    uint8_t *src = malloc(len + 1);

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:
                src[i] = 'c';
                _JUNK_FUN_0
                break;
            case 1:
                src[i] = '5';
                break;
            case 2:
                src[i] = '8';
                break;
            case 3:
                src[i] = '5';
                break;
            case 4:
                src[i] = 'G';
                break;
            case 5:
                src[i] = 'q';
                break;
            case 6:
                src[i] = '0';
                break;
            case 7:
                src[i] = 'Y';
                break;
            case 8:
                src[i] = 'Q';
                break;
            case 9:
                src[i] = 'A';
                break;
            case 10:
                src[i] = '2';
                break;
            case 11:
                src[i] = 'Q';
                _JUNK_FUN_3
                break;
            case 12:
                src[i] = 'U';
                break;
            case 13:
                src[i] = 'l';
                break;
            case 14:
                src[i] = 'M';
                break;
            case 15:
                src[i] = 'c';
                break;
        }
    }
    src[len] = '\0';
    _JUNK_FUN_2
    return src;
}

static const unsigned char HEX[16] = {0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static inline uint8_t *getPaddingInput(const char *input) {
    int inLength = (int) strlen(input); // 输入的长度
    int remainder = inLength % BLOCKLEN;
    uint8_t *paddingInput = NULL;
    int group = inLength / BLOCKLEN;
    size_t size = (size_t) (BLOCKLEN * (group + 1));

    paddingInput = (uint8_t *) malloc(size + 1);

    int dif = (int) size - inLength;
    for (int i = 0; i < size; i++) {
        if (i < inLength) {
            paddingInput[i] = (uint8_t) input[i];
        } else {
            if (remainder == 0) {
                // 刚好是16倍数, 就填充16个16 (0x10)
                paddingInput[i] = HEX[0];
            } else {
                // 如果不足16位 少多少位就补几个几
                paddingInput[i] = HEX[dif];
            }
        }
    }
    paddingInput[size] = '\0';
    return paddingInput;
}

static inline int findPaddingIndex(uint8_t *out, int len) {
    if (out[len - 1] > 0x10) {
        return 0;
    } else {
        return (int) (len - out[len - 1]);
    }
}

static inline void removePadding(uint8_t *out, size_t length) {
    int index = findPaddingIndex(out, length);

    if (index < length) {
        memset(out + index, '\0', length - index);
    }
}


/**
 * AES加密, CBC, PKCS5Padding
 */
char *AES_CBC_PKCS5_Encrypt(const char *input) {
    const uint8_t *AES_KEY = getKey();
    const uint8_t *AES_IV = getIV();

    uint8_t *paddingInput = getPaddingInput(input);
    size_t paddingInputLength = strlen((char *) paddingInput);
    unsigned char *out = (unsigned char *) malloc(paddingInputLength);
    AES_CBC_encrypt_buffer(out, paddingInput, (uint32_t) paddingInputLength, AES_KEY, AES_IV);
    char *hexEn = base64_encode(out, paddingInputLength);

    free(paddingInput);
    free(out);
    free((void *) AES_KEY);
    free((void *) AES_IV);

    return hexEn;
}

/**
 * AES解密, CBC, PKCS5Padding
 */
char *AES_CBC_PKCS5_Decrypt(const char *input) {
    const uint8_t *AES_KEY = getKey();
    const uint8_t *AES_IV = getIV();

    size_t len = strlen(input);
    unsigned char *inputDes = base64_decode(input, len);

    const size_t inputLength = (len / 4) * 3 / BLOCKLEN * BLOCKLEN;
    uint8_t *out = malloc(inputLength);
    memset(out, 0, inputLength);
    AES_CBC_decrypt_buffer(out, inputDes, (uint32_t) inputLength, AES_KEY, AES_IV);

    removePadding(out, inputLength);
    free(inputDes);
    free((void *) AES_KEY);
    free((void *) AES_IV);

    return (char *) out;
}