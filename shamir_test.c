/*
CVaultCentinel project
Author: kuzinandrey@yandex.ru 2024-02-11

Test shamir functions
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shamir.h"
#include "base64.h"

#define KEYSIZE 24
int main() {
	char secret[KEYSIZE];
	char restore[KEYSIZE];
	char key[5][KEYSIZE];
	int fail = 0;

	create_shamir_full(secret, key[0], key[1], key[2], key[3], key[4], KEYSIZE);

	printf("\nSecret: "); base64_printf(secret,KEYSIZE); printf("\n");
	for (int i = 0; i < 5; i++) {
		printf("Key %d: ",i+1);
		base64_printf(key[i],KEYSIZE);
		printf("\n");
	}

	for (int n1 = 1; n1 <= 5; n1++)
	for (int n2 = 1; n2 <= 5; n2++)
	for (int n3 = 1; n3 <= 5; n3++) {
		printf("restore(%d, %d, %d): ", n1, n2, n3);
		int r = restore_shamir_secret(restore, KEYSIZE, n1, key[n1-1], n2, key[n2-1], n3, key[n3-1]);
		if (0 == r) {
			base64_printf(restore,KEYSIZE);
			if (memcmp(secret,restore,KEYSIZE) == 0) {
				printf(" = OK\n");
			} else {
				printf(" = FAIL\n");
				fail++;
			}
		} else {
			printf("ERROR(%d)\n", r);
			if (r < -1) exit(1); // bad, very bad
		}
	};

	return (fail != 0);
} // main()
