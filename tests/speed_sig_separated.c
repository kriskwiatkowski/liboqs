// SPDX-License-Identifier: MIT

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#if defined(USE_RASPBERRY_PI)
#define _RASPBERRY_PI
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
#define SPEED_USE_ARM_PMU
#endif
#include "ds_benchmark.h"
#include "system_info.c"

#define MSG_LEN 50

typedef enum {
	SIG_ACTION_KEYGEN = 1,
	SIG_ACTION_SIGN   = 2,
	SIG_ACTION_VERIFY = 3,
} action_t;

static OQS_STATUS printAlgs(void) {
	for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
		OQS_SIG *c = OQS_SIG_new(OQS_SIG_alg_identifier(i));
		c?printf("%s\n", OQS_SIG_alg_identifier(i)):
		printf("%s (disabled)\n", OQS_SIG_alg_identifier(i));
		OQS_SIG_free(c);
	}
	return OQS_SUCCESS;
}

static bool is_flag(uint8_t t, action_t a) {
	return (t&a) == a;
}

static OQS_STATUS speed_sig(const char *method_name, uint64_t duration, bool printInfo, action_t a) {
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t msg[MSG_LEN] = {0};
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

int main(int argc, char **argv) {

	int ret = EXIT_SUCCESS;
	OQS_STATUS rc;

	bool printUsage = false;
	uint64_t duration = 3;
	bool printSigInfo = false;
	action_t a = SIG_ACTION_KEYGEN | SIG_ACTION_SIGN | SIG_ACTION_VERIFY;
	OQS_SIG *single_sig = NULL;

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
			if (single_sig == NULL) {
				printUsage = true;
				break;
			}
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
	if (single_sig != NULL) {
		rc = speed_sig(single_sig->method_name, duration, printSigInfo, a);
		if (rc != OQS_SUCCESS) {
			ret = EXIT_FAILURE;
		}
	} else {
		for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
			rc = speed_sig(OQS_SIG_alg_identifier(i), duration, printSigInfo, a);
			if (rc != OQS_SUCCESS) {
				ret = EXIT_FAILURE;
			}
		}
	}
	PRINT_TIMER_FOOTER

	return ret;
}
