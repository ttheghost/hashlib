#pragma once
#ifdef __cplusplus
#include <cstdint>
#include <cstring>
#include <climits>

extern "C" {
#else
#include <stdint.h>
#include <string.h>
#include <limits.h>
#endif

/*
 * Bitwise rotate left
*/
static inline uint32_t rotl(uint32_t i, uint32_t n) {
    n = n % (sizeof(i) * CHAR_BIT);
    return (i << n) | (i >> (sizeof(i)*CHAR_BIT - n));
}

/*
 * Bitwise rotate right
*/
static inline uint32_t rotr(uint32_t i, uint32_t n) {
    n = n % (sizeof(i) * CHAR_BIT);
    return (i >> n) | (i << (sizeof(i)*CHAR_BIT - n));
}

#ifdef __cplusplus
}
#endif
