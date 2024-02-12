/*
CVaultCentinel project
Author: kuzinandrey@yandex.ru

Generate gen_table_shamir.h file with crypted data from gen_table.h
This files use in compilation of main cvaultsentinel file.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include<errno.h>

#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "shamir.h"
#include "base64.h"
#include "gen_table.h"

#ifndef KEYSIZE
#define KEYSIZE 24
#endif

int main() {
	char secret[KEYSIZE];
	char key[5][KEYSIZE];
	const char *outname = "gen_table_shamir.h";
	int comma = 0;

	FILE *out = fopen(outname,"w");
	if (!out) {
		fprintf(stderr,"ERROR: can't open file %s\n", outname);
		exit(1);
	}

	create_shamir_full(secret, key[0], key[1], key[2], key[3], key[4], KEYSIZE);

	printf("secret=\""); base64_printf(secret,KEYSIZE); printf("\"\n");
	for (int i = 0; i < 5; i++) {
		printf("key%d=\"%d",i+1,i+1);
		base64_printf(key[i],KEYSIZE);
		printf("\"\n");
	}

	fprintf(out,"#ifndef _CVAULTSENTINEL_GEN_TABLE_SHAMIR_H_\n");
	fprintf(out,"#define _CVAULTSENTINEL_GEN_TABLE_SHAMIR_H_\n");

	FILE *fuuid = fopen("/proc/sys/kernel/random/uuid","r");
	if (!fuuid) {
		fprintf(stderr,"ERROR: can't open uuid file\n");
		exit(1);
	}
	char uuid[128];
	if (!fgets(uuid, sizeof(uuid), fuuid)) {
		fclose(fuuid);
		fprintf(stderr,"ERROR: can't read uuid file\n");
		exit(1);
	} else {
		char *p = uuid + strlen(uuid) - 1;
		while (isspace(*p)) *p-- = '\0';
	};
	fclose(fuuid);

	fprintf(out,"const char *build_id = \"%s\";\n\n", uuid);

	// SHA256 check sum original crypto space
	unsigned char sha256digest[SHA256_DIGEST_LENGTH];

	memset(sha256digest, 0, SHA256_DIGEST_LENGTH);
	SHA256(secret, KEYSIZE, sha256digest);
	fprintf(out, "unsigned char shamir_secret_sha256[] = {");
	comma = 0;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (comma) fprintf(out,","); else comma = 1;
		if (i % 12 == 0) fprintf(out,"\n ");
		fprintf(out, " 0x%02x", sha256digest[i]);
	};
	fprintf(out,"\n};\n\n");

	// NOTE !!! sha256digest after that use in secret key generation
	memset(sha256digest, 0, SHA256_DIGEST_LENGTH);
	SHA256(gen_crypt, gen_crypt_size, sha256digest);
	fprintf(out, "unsigned char gen_crypt_sha256[] = {");
	comma = 0;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (comma) fprintf(out,","); else comma = 1;
		if (i % 12 == 0) fprintf(out,"\n ");
		fprintf(out, " 0x%02x", sha256digest[i]);
	};
	fprintf(out,"\n};\n\n");

	// ENCRYPT
	unsigned char *crypto_buf = NULL;
	size_t crypto_len = 0;
	size_t crypto_size = 0;

	char crypto_by[KEYSIZE * 2]; // 32 + 16 = 48 = 24 * 2 !!!
	unsigned char aes_key[32];
	unsigned char aes_iv[16];
	/*
	 *                24 bytes          24 bytes
	 * crypto_by |    *****       |     *****      |
	 *                  ^secret            ^secret xor sha256
	 *
	 *                32 bytes           16 bytes
	 * AES keys  |    *aes_key*       |  *aes_iv*  |
	 */

	memcpy(crypto_by, secret, KEYSIZE);
	unsigned char *p = crypto_by + KEYSIZE;
	memcpy(p, secret, KEYSIZE);

	for (int i = 0; i < KEYSIZE; i++) *(p + i) ^= sha256digest[i];

	memcpy(aes_key, crypto_by, sizeof(aes_key));
	memcpy(aes_iv, crypto_by + sizeof(aes_key), sizeof(aes_iv));

	crypto_size = gen_crypt_size + 128;
	crypto_len = 0;

	crypto_buf = malloc(crypto_size);
	if (!crypto_buf) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	// MAKE AES 256 CBC
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
		NULL, aes_key, aes_iv)
	) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if(1 != EVP_EncryptUpdate(ctx, crypto_buf, &len,
		gen_crypt, gen_crypt_size)
	) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	crypto_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, crypto_buf + crypto_len, &len)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	crypto_len += len;

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

	// SAVE ENCRYPTED BY SHAMIR SECRET GEN_CRYPT_SPACE
	fprintf(out,"#ifndef _CVAULTSENTINEL_GEN_TABLE_H_\n");
	fprintf(out,"unsigned char *gen_crypt = NULL;\n");
	fprintf(out,"unsigned long gen_crypt_size = 0;\n");
	fprintf(out,"#endif\n\n");

	fprintf(out,"#define SHAMIR_SECRET_SIZE %d\n", KEYSIZE);
	fprintf(out,"char shamir_secret[SHAMIR_SECRET_SIZE] = {0};\n");
	fprintf(out,"int shamir_open = 0;\n");
	fprintf(out,"char shamir_key[5][SHAMIR_SECRET_SIZE] = {0};\n");
	fprintf(out,"int shamir_key_present[5] = {0};\n\n");

	fprintf(out,"unsigned char gen_crypt_shamir[] = {");
	comma = 0;
	for (size_t i = 0; i < crypto_len; i++) {
		if (comma) fprintf(out,","); else comma = 1;
		if (i % 12 == 0) fprintf(out,"\n ");
		// fprintf(out," 0x%02x", gen_crypt[i]);
		fprintf(out," 0x%02x", crypto_buf[i]);
	}
	fprintf(out,"\n};\n\n");
	fprintf(out,"const unsigned long gen_crypt_shamir_size"
		" = sizeof(gen_crypt_shamir) /"
		" sizeof(gen_crypt_shamir[0]);\n");

	free(crypto_buf);

	fprintf(out,"#endif\n\n");

	fclose(out);
} // main()
