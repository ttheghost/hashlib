// Copyright (c) 2026 Mohammed Ifkirne. All rights reserved.
// Use of this source code is governed by the MIT license.
//
// Implementation was off Christoffer Lerno's SHA-1 C3C stdlib implementation

#pragma once

#include "crypto_utils.h"

#ifdef __cplusplus
#include <cstdint>
#include <cstring>

extern "C" {
#else
#include <stdint.h>
#include <string.h>
#endif


#define BLOCK_BYTES 64
#define HASH_BYTES 20

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    char buffer[BLOCK_BYTES];
    char digest[HASH_BYTES];
} sha1;

void sha1_init(sha1 *self);
void sha1_update(sha1 *self, char *data, uint32_t len);
void sha1_final(sha1 *self);
void sha1_transform(uint32_t state[5], char* buffer);

sha1 sha1_hash(char *data, uint32_t len) {
    sha1 cnx;
    sha1_init(&cnx);
    sha1_update(&cnx, data, len);
    sha1_final(&cnx);
    return cnx;
}

void sha1_init(sha1 *self) {
    self->state[0] = 0x67452301;
    self->state[1] = 0xEFCDAB89;
    self->state[2] = 0x98BADCFE;
    self->state[3] = 0x10325476;
    self->state[4] = 0xC3D2E1F0;

    self->count[0] = 0;
    self->count[1] = 0;
    memset(self->buffer, 0, BLOCK_BYTES);
}

void sha1_update(sha1 *self, char *data, uint32_t len) {
    uint32_t j = self->count[0];
    if ((self->count[0] += len << 3) < j) self->count[1]++;
    self->count[1] += len >> 29;
    j = (j >> 3) & 63;
    uint32_t i = 0;
    if (j + len > (BLOCK_BYTES - 1))
    {
        i = BLOCK_BYTES - j;
        memcpy(self->buffer + j, data, i);
        sha1_transform(self->state, self->buffer);
        for (; i + (BLOCK_BYTES - 1)  < len; i+=BLOCK_BYTES)
        {
            sha1_transform(self->state, &data[i]);
        }
        j = 0;
    }
    memcpy(self->buffer + j, data + i, len - i);
}

void sha1_final(sha1 *self) {
    char finalcount[8];
    for (uint32_t i = 0; i < 8; i++)
    {
        finalcount[i] = (char)((self->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }
    sha1_update(self, "\x80", 1);
    while ((self->count[0] & 504) != 448)
    {
        sha1_update(self, "\x00", 1);
    }
    sha1_update(self, finalcount, 8);
    for (uint32_t i = 0; i < HASH_BYTES; i++)
    {
        self->digest[i] = (char)((self->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }
}

typedef union
{
    char c[BLOCK_BYTES];
    uint32_t l[16];
} long16;

static inline uint32_t blk(long16* block, uint64_t i) {
    return (
        block->l[i & 15] =rotl(block->l[(i + 13) & 15]
                           ^ block->l[(i + 8) & 15]
                           ^ block->l[(i + 2) & 15]
                           ^ block->l[i & 15], 1)
    );
}

static inline uint32_t blk0(long16* block, uint64_t i) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || defined(_WIN32) || defined(_WIN64)
        return block->l[i] = (rotl(block->l[i], 24) & 0xFF00FF00 | rotl(block->l[i], 8) & 0x00FF00FF);
    #else
        return block->l[i];
    #endif
}

void r0(long16* block, uint32_t* v, uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z, uint64_t i) {
    *z += ((*w & (*x ^ *y)) ^ *y) + blk0(block, i) + 0x5A827999 + rotl(*v, 5);
    *w = rotl(*w, 30);
}

void r1(long16* block, uint32_t* v, uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z, uint64_t i) {
    *z += ((*w & (*x ^ *y)) ^ *y) + blk(block, i) + 0x5A827999 + rotl(*v, 5);
    *w = rotl(*w, 30);
}

void r2(long16* block, uint32_t* v, uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z, uint64_t i) {
    *z += (*w ^ *x ^ *y) + blk(block, i) + 0x6ED9EBA1 + rotl(*v, 5);
    *w = rotl(*w, 30);
}

void r3(long16* block, uint32_t* v, uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z, uint64_t i) {
    *z += (((*w | *x) & *y) | (*w & *x)) + blk(block, i) + 0x8F1BBCDC + rotl(*v, 5);
    *w = rotl(*w, 30);
}

void r4(long16* block, uint32_t* v, uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z, uint64_t i) {
    *z += (*w ^ *x ^ *y) + blk(block, i) + 0xCA62C1D6 + rotl(*v, 5);
    *w = rotl(*w, 30);
}

void sha1_transform(uint32_t state[5], char* buffer) {
    long16 block;
    memcpy(&block.c, buffer, BLOCK_BYTES);
    uint32_t a = state[0];;
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    r0(&block, &a, &b, &c, &d, &e, 0);
    r0(&block, &e, &a, &b, &c, &d, 1);
    r0(&block, &d, &e, &a, &b, &c, 2);
    r0(&block, &c, &d, &e, &a, &b, 3);
    r0(&block, &b, &c, &d, &e, &a, 4);
    r0(&block, &a, &b, &c, &d, &e, 5);
    r0(&block, &e, &a, &b, &c, &d, 6);
    r0(&block, &d, &e, &a, &b, &c, 7);
    r0(&block, &c, &d, &e, &a, &b, 8);
    r0(&block, &b, &c, &d, &e, &a, 9);
    r0(&block, &a, &b, &c, &d, &e, 10);
    r0(&block, &e, &a, &b, &c, &d, 11);
    r0(&block, &d, &e, &a, &b, &c, 12);
    r0(&block, &c, &d, &e, &a, &b, 13);
    r0(&block, &b, &c, &d, &e, &a, 14);
    r0(&block, &a, &b, &c, &d, &e, 15);
    r1(&block, &e, &a, &b, &c, &d, 16);
    r1(&block, &d, &e, &a, &b, &c, 17);
    r1(&block, &c, &d, &e, &a, &b, 18);
    r1(&block, &b, &c, &d, &e, &a, 19);
    r2(&block, &a, &b, &c, &d, &e, 20);
    r2(&block, &e, &a, &b, &c, &d, 21);
    r2(&block, &d, &e, &a, &b, &c, 22);
    r2(&block, &c, &d, &e, &a, &b, 23);
    r2(&block, &b, &c, &d, &e, &a, 24);
    r2(&block, &a, &b, &c, &d, &e, 25);
    r2(&block, &e, &a, &b, &c, &d, 26);
    r2(&block, &d, &e, &a, &b, &c, 27);
    r2(&block, &c, &d, &e, &a, &b, 28);
    r2(&block, &b, &c, &d, &e, &a, 29);
    r2(&block, &a, &b, &c, &d, &e, 30);
    r2(&block, &e, &a, &b, &c, &d, 31);
    r2(&block, &d, &e, &a, &b, &c, 32);
    r2(&block, &c, &d, &e, &a, &b, 33);
    r2(&block, &b, &c, &d, &e, &a, 34);
    r2(&block, &a, &b, &c, &d, &e, 35);
    r2(&block, &e, &a, &b, &c, &d, 36);
    r2(&block, &d, &e, &a, &b, &c, 37);
    r2(&block, &c, &d, &e, &a, &b, 38);
    r2(&block, &b, &c, &d, &e, &a, 39);
    r3(&block, &a, &b, &c, &d, &e, 40);
    r3(&block, &e, &a, &b, &c, &d, 41);
    r3(&block, &d, &e, &a, &b, &c, 42);
    r3(&block, &c, &d, &e, &a, &b, 43);
    r3(&block, &b, &c, &d, &e, &a, 44);
    r3(&block, &a, &b, &c, &d, &e, 45);
    r3(&block, &e, &a, &b, &c, &d, 46);
    r3(&block, &d, &e, &a, &b, &c, 47);
    r3(&block, &c, &d, &e, &a, &b, 48);
    r3(&block, &b, &c, &d, &e, &a, 49);
    r3(&block, &a, &b, &c, &d, &e, 50);
    r3(&block, &e, &a, &b, &c, &d, 51);
    r3(&block, &d, &e, &a, &b, &c, 52);
    r3(&block, &c, &d, &e, &a, &b, 53);
    r3(&block, &b, &c, &d, &e, &a, 54);
    r3(&block, &a, &b, &c, &d, &e, 55);
    r3(&block, &e, &a, &b, &c, &d, 56);
    r3(&block, &d, &e, &a, &b, &c, 57);
    r3(&block, &c, &d, &e, &a, &b, 58);
    r3(&block, &b, &c, &d, &e, &a, 59);
    r4(&block, &a, &b, &c, &d, &e, 60);
    r4(&block, &e, &a, &b, &c, &d, 61);
    r4(&block, &d, &e, &a, &b, &c, 62);
    r4(&block, &c, &d, &e, &a, &b, 63);
    r4(&block, &b, &c, &d, &e, &a, 64);
    r4(&block, &a, &b, &c, &d, &e, 65);
    r4(&block, &e, &a, &b, &c, &d, 66);
    r4(&block, &d, &e, &a, &b, &c, 67);
    r4(&block, &c, &d, &e, &a, &b, 68);
    r4(&block, &b, &c, &d, &e, &a, 69);
    r4(&block, &a, &b, &c, &d, &e, 70);
    r4(&block, &e, &a, &b, &c, &d, 71);
    r4(&block, &d, &e, &a, &b, &c, 72);
    r4(&block, &c, &d, &e, &a, &b, 73);
    r4(&block, &b, &c, &d, &e, &a, 74);
    r4(&block, &a, &b, &c, &d, &e, 75);
    r4(&block, &e, &a, &b, &c, &d, 76);
    r4(&block, &d, &e, &a, &b, &c, 77);
    r4(&block, &c, &d, &e, &a, &b, 78);
    r4(&block, &b, &c, &d, &e, &a, 79);
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

#ifdef __cplusplus
}
#endif
