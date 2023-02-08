//
// Created by user on 2023/2/6.
//

#ifndef JNIDEMO_BASE64_UTILS_H
#define JNIDEMO_BASE64_UTILS_H

#define base64_encode     abceerfhg
#define base64_decode     ghuykrktu

#ifdef __cplusplus
extern "C" {
#endif

char *base64_encode(const unsigned char *input, size_t len);

unsigned char *base64_decode(const char *input, size_t len);

#ifdef __cplusplus
}
#endif
#endif //JNIDEMO_BASE64_UTILS_H
