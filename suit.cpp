/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cose/crypto.h"
#include "cose.h"
#include "cose_defines.h"
#include "cose/test.h"

static uint8_t buf[2048];

#define CU_ASSERT(A) A
#define CU_ASSERT_EQUAL(A,B) CU_ASSERT(A)
#define CU_ASSERT_EQUAL_FATAL(A,B) CU_ASSERT(A)

// Imported from file 'test-out-signed4.cose'
const unsigned char cose_suite[] = {
	0xd8,0x62,0x84,0x44,0xa1,0x03,0x18,0x2a,0xa0,0x58,0x8a,0x8a,0x01,0xf6,0x46,0xc3,0x12,0x11,0xd1,0xff,0x88,0x1a,0x5b,0x4a,0x42,0xf9,0x82,0x82,0x01,0x50,0xfa,0x6b,0x4a,0x53,0xd5,0xad,0x5f,0xdf,0xbe,0x9d,0xe6,0x63,0xe4,0xd4,0x1f,0xfe,0x82,0x02,0x50,0x14,0x92,0xaf,0x14,0x25,0x69,0x5e,0x48,0xbf,0x42,0x9b,0x2d,0x51,0xf2,0xab,0x45,0xf6,0xf6,0xf6,0xf6,0x87,0x81,0x01,0x10,0xf6,0xf6,0x81,0x01,0xa2,0x01,0x58,
	0x20,0xc3,0x12,0x11,0xd1,0xff,0x88,0xf7,0x7a,0x5a,0xaf,0x65,0x36,0x77,0x89,0x5b,0xfc,0xa7,0x69,0xf0,0x6d,0xa1,0x98,0xa8,0xfa,0x71,0x15,0x6a,0xa6,0x4a,0xcd,0x69,0x5d,0x03,0x58,0x20,0xf7,0xe5,0x9d,0xb5,0xd5,0xef,0x2b,0x6b,0xbb,0x73,0x2d,0xec,0x2e,0x8e,0xf3,0x3c,0x28,0x52,0x24,0xcf,0x7b,0xad,0x23,0x59,0x10,0xe4,0x02,0xb5,0xf5,0x24,0x9c,0x22,0xf6,0x81,0x83,0x58,0x26,0xa2,0x01,0x26,0x04,0x58,0x20,0x9e,
	0x85,0x76,0x97,0xb2,0xd7,0x50,0x68,0xb0,0xea,0x13,0x04,0x7f,0xba,0x82,0xfb,0xe2,0x32,0x48,0x19,0xbf,0x30,0xe0,0xea,0xec,0xf5,0xa6,0xbb,0x6e,0xb6,0x8a,0x5a,0xa0,0x58,0x48,0x30,0x46,0x02,0x21,0x00,0xbd,0xa3,0x26,0xf6,0xd8,0x6c,0x87,0x6c,0xb9,0xae,0xdd,0xd3,0xe9,0x45,0xf1,0x7a,0x65,0x0a,0xae,0x39,0x46,0xea,0x24,0x73,0xce,0xea,0x9a,0x47,0x3b,0x5d,0x86,0xf8,0x02,0x21,0x00,0xfb,0xed,0x42,0x08,0xdd,0x54,
	0x50,0x83,0x8a,0x6f,0xdf,0x59,0xe4,0x2b,0x04,0x4e,0xb7,0x97,0x1f,0xe4,0x53,0xf0,0xd2,0x81,0x8c,0x41,0x3d,0xc8,0xd3,0x0c,0x44,0x3f
};
const unsigned int cose_suite_len = 266;

static uint8_t pk_x [MBEDTLS_ECP_MAX_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0xfb,
    0x16, 0x36, 0x59, 0xb0, 0x86, 0xad, 0x22, 0x27, 0x48, 0xed, 0xe6, 0x44,
    0x0a, 0x10, 0xe6, 0x3a, 0x86, 0x6c, 0xec, 0x6c, 0x08, 0x66, 0x72, 0xa4,
    0x2d, 0x83, 0x19, 0xf9, 0xd2, 0x81,
};
static uint8_t pk_y [MBEDTLS_ECP_MAX_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4b, 0xec,
    0x3f, 0x22, 0x18, 0x51, 0x82, 0x1a, 0xca, 0x58, 0xd8, 0x8b, 0xb2, 0x7b,
    0x3b, 0xd8, 0x27, 0xe0, 0x4a, 0x70, 0xe7, 0x1f, 0x2d, 0x66, 0x81, 0x6a,
    0x3a, 0x08, 0x1e, 0x04, 0xba, 0x4a,
};

static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
}


static void indent(int nestingLevel)
{
    while (nestingLevel--)
        puts("  ");
}

static void dumpbytes(const uint8_t *buf, size_t len)
{
    while (len--)
        printf("%02X ", *buf++);
}


static bool dumprecursive(CborValue *it, int nestingLevel)
{
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);

        indent(nestingLevel);
        switch (type) {
        case CborArrayType:
        case CborMapType: {
            // recursive type
            CborValue recursed;
            assert(cbor_value_is_container(it));
            puts(type == CborArrayType ? "Array[" : "Map[");
            err = cbor_value_enter_container(it, &recursed);
            if (err)
                return err;       // parse error
            err = dumprecursive(&recursed, nestingLevel + 1);
            if (err)
                return err;       // parse error
            err = cbor_value_leave_container(it, &recursed);
            if (err)
                return err;       // parse error
            indent(nestingLevel);
            puts("]");
            continue;
        }

        case CborIntegerType: {
            int64_t val;
            cbor_value_get_int64(it, &val);     // can't fail
            printf("%lld\n", (long long)val);
            break;
        }

        case CborByteStringType: {
            uint8_t *buf;
            size_t n;
            err = cbor_value_dup_byte_string(it, &buf, &n, it);
            if (err)
                return err;     // parse error
            dumpbytes(buf, n);
            puts("");
            free(buf);
            continue;
        }

        case CborTextStringType: {
            char *buf;
            size_t n;
            err = cbor_value_dup_text_string(it, &buf, &n, it);
            if (err)
                return err;     // parse error
            puts(buf);
            free(buf);
            continue;
        }

        case CborTagType: {
            CborTag tag;
            cbor_value_get_tag(it, &tag);       // can't fail
            printf("Tag(%lld)\n", (long long)tag);
            break;
        }

        case CborSimpleType: {
            uint8_t type;
            cbor_value_get_simple_type(it, &type);  // can't fail
            printf("simple(%u)\n", type);
            break;
        }

        case CborNullType:
            puts("null");
            break;

        case CborUndefinedType:
            puts("undefined");
            break;

        case CborBooleanType: {
            bool val;
            cbor_value_get_boolean(it, &val);       // can't fail
            puts(val ? "true" : "false");
            break;
        }

        case CborDoubleType: {
            double val;
            if (false) {
                float f;
        case CborFloatType:
                cbor_value_get_float(it, &f);
                val = f;
            } else {
                cbor_value_get_double(it, &val);
            }
            printf("%g\n", val);
            break;
        }
        case CborHalfFloatType: {
            uint16_t val;
            cbor_value_get_half_float(it, &val);
            printf("__f16(%04x)\n", val);
            break;
        }

        case CborInvalidType:
            assert(false);      // can't happen
            break;
        }

        err = cbor_value_advance_fixed(it);
        if (err)
            return err;
    }
    return CborNoError;
}


int main(void)
{
    cose_sign_t verify;
    cose_key_t signer;
    cose_signature_t signature;
    const uint8_t *kid = NULL;
    /* Initialize struct */
    cose_sign_init(&verify, 0);

    /* First signer */
    cose_key_init(&signer);
    cose_key_set_keys(&signer, COSE_EC_CURVE_P256, COSE_ALGO_ES256, &pk_x[0], &pk_y[0], NULL);

    printf("COSE bytestream: \n");
    print_bytestr(cose_suite, sizeof(cose_suite));
    printf("\n");
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, cose_suite, sizeof(cose_suite));
    printf("Decoding: %d\n", decode_success);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &signature));

    int verification = cose_sign_verify(&verify, &signature, &signer, buf, sizeof(buf));
    printf("Verification: %d\n", verification);
    CU_ASSERT_EQUAL(verification, 0);
    cose_hdr_t hdr;
    CU_ASSERT(cose_sign_get_protected(&verify, &hdr, COSE_HDR_CONTENT_TYPE));
    CU_ASSERT_EQUAL(hdr.v.value, 42);
    ssize_t res = cose_signature_get_kid(&signature, &kid);
    CU_ASSERT(res);
//    CU_ASSERT_EQUAL(memcmp(kid, keyid, sizeof(keyid) - 1), 0);
    printf("Verify Result: %d\n", res);

		CborParser parser;
    CborValue it;
    CborError err = cbor_parser_init(verify.payload, verify.payload_len, 0, &parser, &it);
    if (!err)
        err = dumprecursive(&it, 0);
    free(buf);
}
