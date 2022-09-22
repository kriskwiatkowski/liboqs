// SPDX-License-Identifier: MIT

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

// Needs to be protected for the case when OpenSSL is not compiled.
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#if defined(USE_RASPBERRY_PI)
#define _RASPBERRY_PI
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
#define SPEED_USE_ARM_PMU
#endif
#include "ds_benchmark.h"
#include "system_info.c"

#define MSG_LEN 50
uint8_t msg[MSG_LEN];

typedef enum {
    SIG_ACTION_KEYGEN = 1<<0,
    SIG_ACTION_SIGN   = 1<<1,
    SIG_ACTION_VERIFY = 1<<2,
} action_t;

static void SHA3(const uint8_t *input, size_t inplen, uint8_t *output, const EVP_MD *md) {
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, inplen);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

static inline unsigned char *SHA3_256(const unsigned char *d, size_t n, unsigned char *md) {
    SHA3(d, n, md, EVP_sha3_256());
    return 0;
}

static inline unsigned char *SHA3_384(const unsigned char *d, size_t n, unsigned char *md) {
    SHA3(d, n, md, EVP_sha3_384());
    return 0;
}

static inline unsigned char *SHA3_512(const unsigned char *d, size_t n, unsigned char *md) {
    SHA3(d, n, md, EVP_sha3_512());
    return 0;
}

// ECDSA depending on a curve. This implementation uses SHA256 for NISTp256, SHA384 for NISTp384 and SHA512 for
// NIST p521.
typedef unsigned char *(*ecdsa_dig_t)(const unsigned char *d, size_t n, unsigned char *md);
static const struct ecdig {
    ecdsa_dig_t fn;
    int digest_len;
    int ext_id;
    const char* method_name;
} ecdig[] = {
    {SHA256, SHA256_DIGEST_LENGTH, NID_X9_62_prime256v1,   "ECDSA/p256/SHA2"},
    {SHA384, SHA384_DIGEST_LENGTH, NID_secp384r1,          "ECDSA/p384/SHA2"},
    {SHA512, SHA512_DIGEST_LENGTH, NID_secp521r1,          "ECDSA/p521/SHA2"},
    {SHA3_256, SHA256_DIGEST_LENGTH, NID_X9_62_prime256v1, "ECDSA/p256/SHA3"},
    {SHA3_384, SHA384_DIGEST_LENGTH, NID_secp384r1,        "ECDSA/p384/SHA3"},
    {SHA3_512, SHA512_DIGEST_LENGTH, NID_secp521r1,        "ECDSA/p521/SHA3"},
};
static const size_t ecdig_len = sizeof(ecdig)/sizeof(ecdig[0]);

static OQS_STATUS printAlgs(void) {
    for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
        OQS_SIG *c = OQS_SIG_new(OQS_SIG_alg_identifier(i));
        c?printf("%s\n", OQS_SIG_alg_identifier(i)):
        printf("%s (disabled)\n", OQS_SIG_alg_identifier(i));
        OQS_SIG_free(c);
    }
    for (size_t i=0; i<ecdig_len; i++) {
        printf("%s\n", ecdig[i].method_name);
    }
    return OQS_SUCCESS;
}

static inline const struct ecdig *get_ecdig(int id) {
    size_t i;
    for(i=0; i<sizeof(ecdig)/sizeof(ecdig[0]); i++) {
        if (ecdig[i].ext_id==id) {
            return &ecdig[i];
        }
    }
    return NULL;
}

static inline const struct ecdig *get_ecdig_by_name(const char* n) {
    size_t i;
    for(i=0; i<sizeof(ecdig)/sizeof(ecdig[0]); i++) {
        if (!strcmp(ecdig[i].method_name, n)) {
            return &ecdig[i];
        }
    }
    return NULL;
}

static bool is_flag(action_t t, action_t a) {
    return (t&a) == a;
}

static OQS_STATUS ecdsa_sign(EC_KEY *key, const struct ecdig *ec, uint8_t *s, int *ssz) {
    uint8_t h[SHA512_DIGEST_LENGTH];
    uint8_t sm[132+7]; // result of ecdsa signing with P-521 fits in 66*2 bytes + 7 bytes
                       // as it seems to be ASN.1 encoded (?).
    unsigned int sm_len = (sizeof(sm)/sizeof(sm[0]));

    // Calculate digest of the message
    ec->fn(msg,MSG_LEN,h);
    // Create signature
    (void)ECDSA_sign(0, h, ec->digest_len, sm, &sm_len, key);
    if (ssz && s) {
        memcpy(s, sm, sm_len);
        *ssz = sm_len;
    }
    return OQS_SUCCESS;
}

static OQS_STATUS ecdsa_verify(EC_KEY *key, const struct ecdig *ec, uint8_t *s, int ssz) {
    uint8_t h[SHA512_DIGEST_LENGTH];
    // Calculate digest of the message
    ec->fn(msg,MSG_LEN,h);
    // Create signature
    (void)ECDSA_verify(0, h, ec->digest_len, s, ssz, key);
    return OQS_SUCCESS;
}

static OQS_STATUS speed_sig_pq(const char *method_name, uint64_t duration, bool printInfo, action_t a) {
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *signature = NULL;
    size_t signature_len;
    OQS_STATUS ret = OQS_ERROR;
    OQS_SIG *c;

    c = OQS_SIG_new(method_name);
    if (!c) {
        goto end;
    }

    public_key = malloc(c->length_public_key);
    secret_key = malloc(c->length_secret_key);
    signature = malloc(c->length_signature);
    if (!public_key || !secret_key) {
        fprintf(stderr, "ERROR: malloc failed\n");
        goto end;
    }
    if (OQS_SIG_keypair(c, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Keygen failed.\n");
        goto end;
    }

    printf("%-36s | %10s | %14s | %15s | %10s | %25s | %10s\n", c->method_name, "", "", "", "", "", "");

    if (is_flag(a, SIG_ACTION_KEYGEN)) {
        TIME_OPERATION_SECONDS(
            OQS_SIG_keypair(c, public_key, secret_key), "keypair", duration);
    }

    if (is_flag(a, SIG_ACTION_SIGN) || is_flag(a, SIG_ACTION_VERIFY)) {
        if (OQS_SIG_keypair(c, public_key, secret_key) != OQS_SUCCESS) {
            goto end;
        }
    }
    if (is_flag(a, SIG_ACTION_SIGN)) {
        signature_len = c->length_signature;
        TIME_OPERATION_SECONDS(
            OQS_SIG_sign(c, signature, &signature_len, msg, MSG_LEN, secret_key), "sign", duration);
    }

    if (is_flag(a, SIG_ACTION_VERIFY)) {
        if (OQS_SIG_sign(c, signature, &signature_len, msg, MSG_LEN, secret_key) != OQS_SUCCESS) {
            goto end;
        }
        TIME_OPERATION_SECONDS(
            OQS_SIG_verify(c, msg, MSG_LEN, signature, signature_len, public_key), "verify", duration);
    }

    if (printInfo) {
        printf("public key bytes: %zu, secret key bytes: %zu, signature bytes: %zu\n", c->length_public_key, c->length_secret_key, c->length_signature);
    }

    ret = OQS_SUCCESS;

end:
    OQS_MEM_secure_free(secret_key, c->length_secret_key);
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_insecure_free(signature);
    OQS_SIG_free(c);
    return ret;
}

static OQS_STATUS speed_sig_ec(const struct ecdig *e, uint64_t duration, bool printInfo, action_t a) {
    OQS_STATUS ret = OQS_ERROR;
    uint8_t s[1024] = {0}; int ssz;
    if (!e) {
        return OQS_ERROR;
    }

    printf("%-36s | %10s | %14s | %15s | %10s | %25s | %10s\n", e->method_name, "", "", "", "", "", "");
    EC_KEY* key = EC_KEY_new_by_curve_name(e->ext_id);
    if (!key) {
        return OQS_ERROR;
    }

    if (is_flag(a, SIG_ACTION_KEYGEN)) {
        TIME_OPERATION_SECONDS(EC_KEY_generate_key(key), "keygen", duration);
    }

    if (is_flag(a, SIG_ACTION_SIGN)) {
        if (!EC_KEY_generate_key(key)) {
            goto end;
        }
        TIME_OPERATION_SECONDS(ecdsa_sign(key, e, 0, 0), "sign", duration);
    }

    if (is_flag(a, SIG_ACTION_VERIFY)) {
        if (!EC_KEY_generate_key(key) || ecdsa_sign(key, e, s, &ssz) != OQS_SUCCESS) {
            goto end;
        }
        TIME_OPERATION_SECONDS(ecdsa_verify(key, e, s, ssz), "verify", duration);
    }
    if (printInfo) {
        printf("signature bytes: %u\n", ssz);
    }
    ret = OQS_SUCCESS;

end:
    EC_KEY_free(key);
    return ret;
}

int main(int argc, char **argv) {

    int ret = EXIT_SUCCESS;
    OQS_STATUS rc;

    bool printUsage = false;
    uint64_t duration = 3;
    bool printSigInfo = false;
    action_t a = SIG_ACTION_KEYGEN | SIG_ACTION_SIGN | SIG_ACTION_VERIFY;
    OQS_SIG *single_sig = NULL;
    char alg_name[1024] = {0};
    bool alg_found = false;

    OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--algs") == 0) {
            rc = printAlgs();
            if (rc == OQS_SUCCESS) {
                return EXIT_SUCCESS;
            } else {
                return EXIT_FAILURE;
            }
        } else if ((strcmp(argv[i], "--duration") == 0) || (strcmp(argv[i], "-d") == 0)) {
            if (i < argc - 1) {
                duration = (uint64_t)strtol(argv[i + 1], NULL, 10);
                if (duration > 0) {
                    i += 1;
                    continue;
                }
            }
        } else if ((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0)) {
            printUsage = true;
            break;
        } else if ((strcmp(argv[i], "--info") == 0) || (strcmp(argv[i], "-i") == 0)) {
            printSigInfo = true;
            continue;
        } else if ((strcmp(argv[i], "--action") == 0) || (strcmp(argv[i], "-a") == 0)) {
            switch (argv[i + 1][0]) {
                case 'k': a = SIG_ACTION_KEYGEN; break;
                case 's': a = SIG_ACTION_SIGN;   break;
                case 'v': a = SIG_ACTION_VERIFY; break;
                default: return EXIT_FAILURE;
            }
            i++;
            continue;
        } else {
            single_sig = OQS_SIG_new(argv[i]);
            alg_found = single_sig || get_ecdig_by_name(argv[i]);
            if (!alg_found) {
                printUsage = true;
                break;
            }
            memcpy(alg_name, argv[i], strlen(argv[i]));
        }
    }

    if (printUsage) {
        fprintf(stderr, "Usage: speed_sig <options> <alg>\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "<options>\n");
        fprintf(stderr, "--algs             Print supported algorithms and terminate\n");
        fprintf(stderr, "--duration n\n");
        fprintf(stderr, " -d n              Run each speed test for approximately n seconds, default n=3\n");
        fprintf(stderr, "--help\n");
        fprintf(stderr, " -h                Print usage\n");
        fprintf(stderr, "--info\n");
        fprintf(stderr, " -i                Print info (sizes, security level) about each SIG\n");
        fprintf(stderr, "--action\n");
        fprintf(stderr, " -a                Run specific action (keygen, sign, verify)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "<alg>              Only run the specified SIG method; must be one of the algorithms output by --algs\n");
        return EXIT_FAILURE;
    }

    print_system_info();

    printf("Speed test\n");
    printf("==========\n");

    PRINT_TIMER_HEADER;
    if (alg_found) {
        if (single_sig) {
            rc = speed_sig_pq(single_sig->method_name, duration, printSigInfo, a);
            if (rc != OQS_SUCCESS) {
                ret = EXIT_FAILURE;
            }
        } else {
            const struct ecdig *e = get_ecdig_by_name(alg_name);
            if (!e) {
                ret = EXIT_FAILURE;
            } else {
                rc = speed_sig_ec(e, duration, printSigInfo, a);
                if (rc != OQS_SUCCESS) {
                    ret = EXIT_FAILURE;
                }
            }
        }
    } else {
        for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
            rc = speed_sig_pq(OQS_SIG_alg_identifier(i), duration, printSigInfo, a);
            if (rc != OQS_SUCCESS) {
                ret = EXIT_FAILURE;
            }
        }
        for (size_t i=0; i<ecdig_len; i++) {
            speed_sig_ec(&ecdig[i], duration, printSigInfo, a);
        }
    }
    PRINT_TIMER_FOOTER;

    return ret;
}
