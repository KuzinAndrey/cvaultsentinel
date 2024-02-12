/*
CVaultCentinel project
Author: kuzinandrey@yandex.ru 2024-02-11

Shamir shared secrets theory:
EN: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
RU: https://ru.wikipedia.org/wiki/%D0%A1%D1%85%D0%B5%D0%BC%D0%B0_%D1%80%D0%B0%D0%B7%D0%B4%D0%B5%D0%BB%D0%B5%D0%BD%D0%B8%D1%8F_%D1%81%D0%B5%D0%BA%D1%80%D0%B5%D1%82%D0%B0_%D0%A8%D0%B0%D0%BC%D0%B8%D1%80%D0%B0
*/

#ifndef SHAMIR_HEADER_H
#define SHAMIR_HEADER_H

#include <stdlib.h>
#include <sys/time.h>

// Hardcode the shamir prime number for use in HEX(4 bit) numbers mathematics
#define SHAMIR_PRIME 13

/*
 * Shamir function
 */
int shamir_f(int n, int a, int b, int secret) {
	// f(n) = (a * n^2 + b * n + S) mod P
	return (a * n * n + b * n + secret) % SHAMIR_PRIME;
}

/*
 * Calculame shamir secret part by three shared numbers
 */
int shamir(int n1, int k1, int n2, int k2, int n3, int k3) {
	/*
	Bruteforce the system of equations:
	 / (a * n1^2 + b * n1 + S) % p = k1
	<  (a * n2^2 + b * n2 + S) % p = k2
	 \ (a * n3^2 + b * n3 + S) % p = k3
	*/
	for (int a = 0; a <= SHAMIR_PRIME; a++)
	for (int b = 0; b <= SHAMIR_PRIME; b++)
	for (int s = 0; s <= SHAMIR_PRIME; s++)
	if (
		(shamir_f(n1, a, b, s) == k1) &&
		(shamir_f(n2, a, b, s) == k2) &&
		(shamir_f(n3, a, b, s) == k3)
	) return s;
	return -1; // unreachable place
}

/*
 * Generate one secret and 5 shared secrets in buffers
 * Buffers must be the same length in `size` bytes
 */
void create_shamir_full(char *secret, char *k1, char *k2, char *k3, char *k4, char *k5, size_t size) {
	int a,b,s,d[5],n,l;
	size_t count = 0;
	struct timeval tv;
	gettimeofday(&tv,NULL);
	srand(tv.tv_sec ^ tv.tv_usec);
	while (1) {
		a = rand() % SHAMIR_PRIME;
		b = rand() % SHAMIR_PRIME;
		s = rand() % SHAMIR_PRIME;
		for (int i = 0; i < 5; i++) {
			d[i] = shamir_f(i + 1, a, b, s);
		};
		n = (count / 2) % size;
		l = count % 2;
		if (l == 0) {
			secret[n] = s << 4;
			k1[n] = d[0] << 4;
			k2[n] = d[1] << 4;
			k3[n] = d[2] << 4;
			k4[n] = d[3] << 4;
			k5[n] = d[4] << 4;
		} else if (l == 1) {
			secret[n] |= s;
			k1[n] |= d[0];
			k2[n] |= d[1];
			k3[n] |= d[2];
			k4[n] |= d[3];
			k5[n] |= d[4];
		}
		if (n == size - 1 && l == 1) break;
		count++;
	} // while
} // create_shamir_full()

/*
Restore shamir secret key by 3 shared secrets
All numbers of keys must be in 1..5 (starting from 1 !)
Return 0 on success
Return negative on error
*/
int restore_shamir_secret(char *secret, size_t size,
	int num1, const char *key1,
	int num2, const char *key2,
	int num3, const char *key3) {

	if ((num1 == num2) || (num1 == num3) || (num2 == num3)) return -1;
	int r1, r2;

	for (int i = 0; i < size; i++) {
		r1 = shamir(num1, (key1[i] >> 4) & 0xF, num2,
			(key2[i] >> 4) & 0xF,  num3, (key3[i] >> 4) & 0xF);

		r2 = shamir(num1, key1[i] & 0xF, num2,
			key2[i] & 0xF, num3, key3[i] & 0xF);

		if (r1 < 0 || r2 < 0) return -2;
		secret[i] = (r1 << 4) | (r2 & 0xF);
	}

	return 0;
} // restore_shamir_secret()

#endif /* SHAMIR_HEADER_H */
