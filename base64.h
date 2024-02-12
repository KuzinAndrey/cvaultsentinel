#ifndef BASE64_HEADER_H
#define BASE64_HEADER_H

#include <stdio.h>

const char base64[]=
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void base64_fprintf(FILE *stream, char *v, size_t s) {
	unsigned char b64line[75];
	size_t b64line_len = 0;
	size_t remain = s;
	unsigned char *p = (unsigned char *)v, *o = b64line;
	while (remain >= 3) {
		*o++ = base64[p[0] >> 2];
		*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
		*o++ = base64[((p[1] & 0x0F) << 2) | (p[2] >> 6)];
		*o++ = base64[p[2] & 0x3F];
		remain -= 3;
		p+=3;
		b64line_len += 4;
		if (b64line_len >= 72) {
			*o++ = '\0';
			fprintf(stream, "%s\n", b64line);
			o = b64line;
			b64line_len = 0;
		}
	}
	if (remain > 0) {
		*o++ = base64[p[0] >> 2];
		if (remain == 1) {
			*o++ = base64[(p[0] & 0x03) << 4];
			*o++ = '=';
		} else {
			*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
			*o++ = base64[(p[1] & 0x0F) << 2];
		}
		*o++ = '=';
		b64line_len += 4;
	}
	*o++ = '\0';
	if (b64line_len > 0) fprintf(stream, "%s", b64line);
}

void base64_printf(char *v, size_t s) {
	base64_fprintf(stdout, v, s);
}

#endif /* BASE64_HEADER_H */
