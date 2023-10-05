/*
 * CVaultSentinel HTTP API daemon (for encrypt/decrypt data)
 *
 * Author: Kuzin Andrey, 2023-10-02
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <event.h>
#include <event2/thread.h>
#include <evhttp.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "gen_table.h"

#ifdef PRODUCTION_MODE
#define TRACEFUNC
#define TRACE
#define DEBUG(...) {}
#else
#define TRACEFUNC fprintf(stderr,"TRACEFUNC %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#endif

#define HTTP_THREADS_CAP 2
#define HTTP_LISTEN_PORT 6969
#define HTTP_MAX_CONNECTIONS 1024

#define W(...) evbuffer_add_printf(buf, __VA_ARGS__)

#define PROJECT_TITLE "CVaultSentinel"

#define HTTP_UNAUTHORIZED 401

static time_t global_start_time = 0;
static int global_need_refresh = 0;

#define XOR_BLOCK_NUM 4
struct xor_block_st {
	int num;
	pthread_t thread;
	pthread_mutex_t mutex;
	uint32_t key;
}; 
static struct xor_block_st xor_data[XOR_BLOCK_NUM] = {0};

static const char base64[]=
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static char base64dec[256] = {0};

// Multithreaded HTTP server
struct http_worker {
	int id;
	pthread_t thread;
	struct event_base *base;
	struct evhttp *http;

	size_t request_count;
	size_t send_bytes;
}; // struct http_worker

static struct http_worker workers[HTTP_THREADS_CAP];
static int http_server_socket = -1;
static int http_server_running = 0;

// HTTP server based on event2 library
int http_bind_socket() {
	TRACEFUNC

	int r;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Error: can't create socket\n");
		return -1;
	}

	int one = 1;
	r = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(int));

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // INADDR_ANY;
	addr.sin_port = htons(HTTP_LISTEN_PORT);

	r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (r < 0) {
		fprintf(stderr, "Error: can't bind socket\n");
		return -1;
	}
	r = listen(sockfd, HTTP_MAX_CONNECTIONS);
	if (r < 0) {
		fprintf(stderr, "Error: can't listen socket\n");
		return -1;
	}

	int flags;
	if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0
		|| fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fprintf(stderr, "Error: can't fcntl socket\n");
		return -1;
	}

	return sockfd;
} // http_bind_socket()

void *http_dispatch(void *arg) {
	TRACEFUNC

	struct http_worker *w = (struct http_worker *) arg;
	event_base_dispatch(w->base);

	pthread_exit(NULL);
} // http_dispatch()

// HTTP callbacks definitions
typedef int (*function_url_handler_t)(struct evhttp_request *, struct evbuffer *);
int www_root_handler(struct evhttp_request *, struct evbuffer *);
int www_status_handler(struct evhttp_request *, struct evbuffer *);
int www_encrypt_handler(struct evhttp_request *, struct evbuffer *);
int www_decrypt_handler(struct evhttp_request *, struct evbuffer *);
#ifndef PRODUCTION_MODE
int www_blockinfo_handler(struct evhttp_request *, struct evbuffer *);
#endif

// Array of URL's served by HTTP
struct http_uri {
	char *uri;
	char *content_type; // if NULL - "text/html;charset=utf-8"
	function_url_handler_t handler;
} http_uri_list[] = {
	{ "/", NULL, &www_root_handler}
	,{ "/status", NULL, &www_status_handler}
	,{ "/encrypt", NULL, &www_encrypt_handler}
	,{ "/decrypt", NULL, &www_decrypt_handler}
#ifndef PRODUCTION_MODE
	,{ "/blockinfo", NULL, &www_blockinfo_handler}
#endif
	,{ NULL, NULL, NULL} // end of list
}; // http_uri_list

void http_process_request(struct evhttp_request *req, void *arg) {
	TRACEFUNC

	struct http_worker *w = (struct http_worker *)arg;
	if (!w) return;

	w->request_count++;

	int http_code = HTTP_NOTFOUND; // default "Page not found"
	const char *http_message = "Page not found";
	const char *conttype = "text/html;charset=utf-8";
	struct evhttp_uri *uri_parsed = NULL;

	uri_parsed = evhttp_uri_parse(req->uri);
	if (!uri_parsed) {
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		evhttp_send_error(req, HTTP_INTERNAL, "Can't allocate memory for reply");
		if (uri_parsed) evhttp_uri_free(uri_parsed);
		return;
	}

	char *path = evhttp_decode_uri(evhttp_uri_get_path(uri_parsed));
	if (path) {
		struct http_uri *u = http_uri_list;
		while (u->uri) {
			if (0 == strcmp(path, u->uri)) {
				if (u->content_type) conttype = u->content_type;
				http_code = u->handler(req, buf);
				break;
			}
			u++;
		} // while
		free(path);
	} else http_code = HTTP_INTERNAL;
	
	switch (http_code) {
	case HTTP_OK:
		evhttp_add_header(req->output_headers, "Expires", "Mon, 01 Jan 1995 00:00:00 GMT");
		evhttp_add_header(req->output_headers, "Cache-Control", "no-cache, must-revalidate");
		evhttp_add_header(req->output_headers, "Pragma", "no-cache");
		if (strlen(conttype) > 0) {
			evhttp_add_header(req->output_headers, "Content-type", conttype);
		};
		w->send_bytes += evbuffer_get_length(buf);
		http_message = "OK";
		break;
	case HTTP_UNAUTHORIZED: http_message = "Unauthorized"; break;
	case HTTP_BADREQUEST: http_message = "Wrong request"; break;
	case HTTP_NOTFOUND: http_message = "Not found"; break;
	case HTTP_MOVEPERM: http_message = "Moved Permanently"; break;
	case HTTP_BADMETHOD: http_message = "Bad method"; break;
	default:
		http_code = HTTP_INTERNAL;
		http_message = "Internal server error";
	} // switch
	evhttp_send_reply(req, http_code, http_message, buf);

	if (buf) evbuffer_free(buf);
	if (uri_parsed) evhttp_uri_free(uri_parsed);
} // http_process_request()

// Main signal handler
void signal_handler(int sig) {
	TRACEFUNC
	int i;
	switch (sig) {
	case SIGTERM: case SIGINT: case SIGQUIT:
		for (i = 0; i < HTTP_THREADS_CAP; i++)
			if (workers[i].base)
				event_base_loopbreak(workers[i].base);
		http_server_running = 0;
		break;
	case SIGHUP:
		global_need_refresh = 1;
		break;
	} // swtich
} // signal_handler

//  modify password data with xor (protection from Meltdown, Spectre type of attack)
void *xor_block(void *data) {
	TRACEFUNC

	struct xor_block_st *me = data;
	DEBUG("block = %d\n",me->num);
	while (http_server_running != 1) {};

	size_t myblock_len = gen_crypt_size / sizeof(uint32_t) / XOR_BLOCK_NUM;
	uint32_t *myblock = (uint32_t *)&gen_crypt[me->num * (gen_crypt_size / XOR_BLOCK_NUM)];
	
	while (http_server_running) {
		uint32_t new_xor_code = rand();
		pthread_mutex_lock(&me->mutex);
		for (size_t i = 0; i < myblock_len; ++i) {
			myblock[i] = myblock[i] ^ me->key ^ new_xor_code;
		}
		me->key = new_xor_code;
		pthread_mutex_unlock(&me->mutex);
		sleep(1);
	} // while
	pthread_exit(NULL);
} // xor_block()

char *get_gen_crypt_part(size_t start, void *buf, size_t buf_size) {
	size_t xor_block_size = gen_crypt_size / XOR_BLOCK_NUM;
	start %= gen_crypt_size;
	size_t block_start = (start % gen_crypt_size) / xor_block_size;
	size_t block_end = ((start + buf_size) % gen_crypt_size) / xor_block_size;

	uint32_t k[16]; // this is enought for AES key and iv arrays (don't use heap)
	// uint32_t *k = calloc(buf_size / sizeof(uint32_t) + 2, sizeof(uint32_t));
	// if (!k) return NULL;

	size_t si = start / sizeof(uint32_t) % (xor_block_size / sizeof(uint32_t));
	size_t se = ((start + buf_size) / sizeof(uint32_t) + 1) % (xor_block_size / sizeof(uint32_t));
	uint32_t *block = (uint32_t *)&gen_crypt[block_start * xor_block_size];

	size_t e = xor_block_size / sizeof(uint32_t) - si; // вышли за пределы блока
	if (se >= si) e = se - si; // в пределах одного блока
	uint32_t *p = k;
	pthread_mutex_lock(&xor_data[block_start].mutex);
		for (size_t i = 0; i <= e; ++i)
			*p++ = block[si + i] ^ xor_data[block_start].key;
	pthread_mutex_unlock(&xor_data[block_start].mutex);

	if (se < si) {
		block = (uint32_t *)&gen_crypt[block_end * xor_block_size];
		pthread_mutex_lock(&xor_data[block_end].mutex);
		for (size_t i = 0; i <= se; ++i)
			*p++ = block[i + 1] ^ xor_data[block_end].key;
		pthread_mutex_unlock(&xor_data[block_end].mutex);
	}

	memcpy(buf, (char *)k + start % sizeof(uint32_t), buf_size);
	// free(k);
	return buf;
}


/*
 * MAIN
 */
int main(int argc, char **argv) {
	const int sig_array[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT };

	tzset();
	global_start_time = time(NULL);
	srand(global_start_time);

	memset(base64dec, 0x80, sizeof(base64dec));
	for (int i = 0; i < sizeof(base64) - 1; i++)
		base64dec[(int)base64[i]] = (unsigned char) i;
	base64dec['='] = 0;

	evthread_use_pthreads();

	http_server_socket = http_bind_socket();
	if (http_server_socket < 0) {
		fprintf(stderr, "Error: can't call http_bind_socket()\n");
		return 1;
	};
	
	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		workers[i].id = i;

		workers[i].base = event_init();
		if (!workers[i].base) {
			fprintf(stderr, "Error: can't init event_base() for worker #%d\n",i);
			return 2;
		}

		workers[i].http = evhttp_new(workers[i].base);
		if (!workers[i].http) {
			fprintf(stderr, "Error: can't init event_base() for worker #%d\n",i);
			return 3;
		}

		if (0 != evhttp_accept_socket(workers[i].http, http_server_socket)) {
			fprintf(stderr, "Error: can't run evhttp_accept_socket()\n");
			return 4;
		}

		evhttp_set_gencb(workers[i].http, http_process_request, (void *)&workers[i]);
		if (0 != pthread_create(&workers[i].thread, NULL, http_dispatch, (void *)&workers[i])) {
			fprintf(stderr, "Error: can't create pthread with %s()\n","http_dispatch");
			return 5;
		};
	} // for accept

	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		xor_data[i].num = i;
		xor_data[i].key = 0;
		pthread_mutex_init(&xor_data[i].mutex, NULL);
		if (0 != pthread_create(&xor_data[i].thread, NULL, xor_block, (void *)&xor_data[i])) {
			fprintf(stderr, "Error: can't create pthread with %s()\n","xor_block");
			return 6;
		}
		DEBUG("Thread #%d = %ld (num = %d)\n", i, xor_data[i].thread, xor_data[i].num);
	}
	http_server_running = 1;

#ifdef PRODUCTION_MODE
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		return 7;
	};
#endif

	for (int i = 0; i < sizeof(sig_array) / sizeof(sig_array[0]); i++)
		signal(sig_array[i], signal_handler);
		
	while (http_server_running) {
		// receive HUP signal to reload data
		if (global_need_refresh == 1) {
			// TODO here refresh config or any
			global_need_refresh = 0;
		}

		// TODO something every second

		sleep(1);
	} // while

	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		pthread_join(workers[i].thread, NULL);
	} // for join

	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		pthread_join(xor_data[i].thread, NULL);
	} // for join

	return 0;
} // main()

/*
 * HTTP URL: /
 * Main page of HTTP server
 */
int www_root_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;

	W("<html>");
	W("<head>");
	W("<title>%s</title>",PROJECT_TITLE);
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s</h1>",PROJECT_TITLE);

	W("<ul>"
	"<li><a href=/status>Status</a>"
	);
#ifndef PRODUCTION_MODE
	for (int i = 0; i < XOR_BLOCK_NUM; i++) {
		W("<li><a href=/blockinfo?block=%d>XOR block #%d</a>",i,i);
	}
#endif
	W(
	"</ul>"
	);
	W("<p>By avkuzin@rt-dc.ru 2024-10-04</p>");
	W("</body>");
	W("</html>");

	return HTTP_OK;
} // www_root_handler()


/*
 * HTTP URL: /status
 * Statistics page for HTTP server
 */
int www_status_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;
	size_t total_req = 0, total_bytes = 0;
	char tm_buff[100];
	struct tm tm_st;

	W("<html>");
	W("<head>");
	W("<title>%s: %s</title>",PROJECT_TITLE,"Status page");
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s: %s</h1>",PROJECT_TITLE,"Status page");
	W("<pre>");
	time_t now_time = time(NULL);
	localtime_r(&global_start_time, &tm_st);
	sprintf(tm_buff, "%04d-%02d-%02d %02d:%02d:%02d", tm_st.tm_year + 1900, tm_st.tm_mon + 1, tm_st.tm_mday,
		tm_st.tm_hour, tm_st.tm_min, tm_st.tm_sec);

	W("Start time: %s\n", tm_buff);
	W("Uptime: %lu secs\n", (long)(now_time - global_start_time));
	W("Remote host: %s\n", req->remote_host);
	W("Size of crypto table: %lu\n", gen_crypt_size);
	W("===================\n");
	for (int i = 0; i < HTTP_THREADS_CAP; i++) {
		W("Thread #%d - requests %lu, send bytes %lu\n",
			workers[i].id, workers[i].request_count, workers[i].send_bytes);
		total_req += workers[i].request_count;
		total_bytes += workers[i].send_bytes;
	};
	W("===================\n"
	"Total requests: %lu\n"
	"Total send bytes %lu\n",
	total_req, total_bytes);
	W("</pre>");
	W("<p><a href=/>[back]</a></p>");

	return HTTP_OK;
} // www_status_handler()


#ifndef PRODUCTION_MODE
/*
 * HTTP URL: /www_blockinfo_handler
 * Info page for N block of gen_crypt
 */
int www_blockinfo_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC

	if (!req || !buf) return HTTP_INTERNAL;

	struct evkeyvalq urls;
	struct evkeyval *url;
	const char *uri;

	char *block = NULL;

	uri = evhttp_request_get_uri(req);
	if (uri && evhttp_parse_query(uri, &urls) == 0) {
		for (url = (&urls)->tqh_first; url; url = url->next.tqe_next) {
			if (strcmp("block", url->key) == 0) { block = url->value; continue; }
		}
	} else return HTTP_BADREQUEST;

	if (!block) return HTTP_BADREQUEST; // HTTP 400

	int num = atoi(block);

	W("<html>");
	W("<head>");
	W("<title>%s: %s</title>",PROJECT_TITLE,"Block info");
	W("</head>");
	W("<body bgcolor=white link=blue>");
	W("<h1>%s: %s</h1>",PROJECT_TITLE,"Block info");
	if (num >= 0 && num < XOR_BLOCK_NUM) {
		W("<pre>");
		W("Block #: %d\n", num);
		pthread_mutex_lock(&xor_data[num].mutex);
			W("Temp XOR key: %" PRIu32 "\n", xor_data[num].key);
			W("Data (first 256 bytes):\n");
			size_t start_addr = gen_crypt_size / XOR_BLOCK_NUM * num;
			for (int i = 0; i <= 0xFF; i++) {
				if (i % 16 == 0 && i > 0) W("\n");
				W("%02X ", gen_crypt[start_addr + i]);
			}
		pthread_mutex_unlock(&xor_data[num].mutex);
		W("</pre>");
		W("<p><a href=/>[back]</a></p>");
	} else {
		W("<p><font color=red>Wrong block number: %d</font></p>",num);	
	}
	W("</body>");
	W("</html>");

	return HTTP_OK;
} // www_status_handler()
#endif


/*
 * HTTP URL: /www_encrypt_handler
 * Encrypt data block
 */
int www_encrypt_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;

	struct evbuffer *reqinbuf;
	int http_ret = HTTP_OK;

	unsigned char *input_buf = NULL;
	size_t input_len = 0;
	size_t input_size = 0;

	unsigned char *crypto_buf = NULL;
	size_t crypto_len = 0;
	size_t crypto_size = 0;

	int key_pos = rand();
	int iv_pos = rand();
	unsigned char key[32];
	unsigned char iv[16];

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		return HTTP_BADMETHOD;
	}

	if (get_gen_crypt_part(key_pos, key, sizeof(key)) == NULL
		|| get_gen_crypt_part(iv_pos, iv, sizeof(iv)) == NULL) {
		return HTTP_INTERNAL;
	};

	input_size = 1024;
	input_buf = malloc(input_size);
	if (!input_buf) {
		DEBUG("Can't allocate memory %ld\n", input_size);
		return HTTP_INTERNAL;
	}

	reqinbuf = evhttp_request_get_input_buffer(req);

	while (evbuffer_get_length(reqinbuf)) {
		unsigned char buf[256];
		int n;
		n = evbuffer_remove(reqinbuf, buf, sizeof(buf));
		if (n > 0) {
			if (input_len + n >= input_size) {
				unsigned char *r;
				r = realloc(input_buf, input_size * 2);
				if (!r) {
					http_ret = HTTP_INTERNAL;
					goto _exit;
				}
				input_buf = r;
				input_size *= 2;
			}
			memcpy(input_buf + input_len, buf, n);
			input_len += n;
		}
	};

	crypto_size = input_len + 128; // extra space for encryption padding & any addon data
	crypto_buf = malloc(crypto_size);
	if (!crypto_buf) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	memcpy(crypto_buf, &key_pos, sizeof(int));
	crypto_len += sizeof(int);
	
	memcpy(crypto_buf + crypto_len, &iv_pos, sizeof(int));
	crypto_len += sizeof(int);
	

/////// MAKE AES 256 CBC ////////
	EVP_CIPHER_CTX *ctx = NULL;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	int len;
	if(1 != EVP_EncryptUpdate(ctx, crypto_buf + crypto_len, &len, input_buf, input_len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	crypto_len += len;

	if(1 != EVP_EncryptFinal_ex(ctx, crypto_buf + crypto_len, &len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	crypto_len += len;
		
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
///////////////
	// W("<pre>");
	// W("key = %d\n", key_pos);
	// W("iv = %d\n", iv_pos);
	// W("length = %ld\n", input_len);
	// W("size = %ld\n", input_size);
	// W("crypto_length = %ld\n", crypto_len);
	// W("crypto_size = %ld\n", crypto_size);

	// W("Original:\n");
	// for (size_t i = 0; i < input_len; i++) {
	// 	if (i % 16 == 0 && i > 0) W("\n");
	// 	W("%02X ", (char)input_buf[i] & 0xFF);
	// }

	// W("\n\nCrypto:\n");
	unsigned char b64line[75];
	size_t b64line_len = 0;
	size_t remain = crypto_len;
	unsigned char *p = crypto_buf, *o = b64line;
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
			W("%s\n",b64line);
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
	if (b64line_len > 0) W("%s\n",b64line);

	// for (size_t i = 0; i < crypto_len; i++) {
	// 	if (i % 16 == 0 && i > 0) W("\n");
	// 	W("%02X ", (char)crypto_buf[i] & 0xFF);
	// }

	// W("</pre>");

_exit:
	if (input_buf) free(input_buf);
	if (crypto_buf) free(crypto_buf);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	return http_ret;
} // www_encrypt_handler()


/*
 * HTTP URL: /www_decrypt_handler
 * Decrypt data block
 */
int www_decrypt_handler(struct evhttp_request *req, struct evbuffer *buf) {
	TRACEFUNC
	if (!req || !buf) return HTTP_INTERNAL;

	struct evbuffer *reqinbuf;
	int http_ret = HTTP_OK;
	int key_pos = 0;
	int iv_pos = 0;
	unsigned char key[32];
	unsigned char iv[16];

	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		return HTTP_BADMETHOD;
	}

	unsigned char *input_buf = NULL;
	size_t input_len = 0;
	size_t input_size = 0;

	unsigned char *crypto_buf = NULL;
	size_t crypto_size = 0;

	input_size = 1024;
	input_buf = malloc(input_size);
	if (!input_buf) {
		DEBUG("Can't allocate memory %ld\n", input_size);
		return HTTP_INTERNAL;
	}

	reqinbuf = evhttp_request_get_input_buffer(req);
	while (evbuffer_get_length(reqinbuf)) {
		unsigned char buf[256];
		int n;
		n = evbuffer_remove(reqinbuf, buf, sizeof(buf));
		if (n > 0) {
			if (input_len + n >= input_size) {
				unsigned char *r;
				r = realloc(input_buf, input_size * 2);
				if (!r) {
					http_ret = HTTP_INTERNAL;
					goto _exit;
				}
				input_buf = r;
				input_size *= 2;
			}
			memcpy(input_buf + input_len, buf, n);
			input_len += n;
		}
	};

	// base64dec
	size_t out_len = 0;
	unsigned char block[4];
	unsigned char ch;
	int pos = 0;
	unsigned char *out = input_buf;
	int pad = 0;
	for (size_t i = 0; i < input_len; i++) {
		ch = base64dec[input_buf[i]];
		if (ch == 0x80) continue; // skip unknown chars
		if (input_buf[i] == '=') pad++;
		block[pos++] = ch;
		if (pos == 4) {
			*out++ = (block[0] << 2) | (block[1] >> 4);
			*out++ = (block[1] << 4) | (block[2] >> 2);
			*out++ = (block[2] << 6) | block[3];
			pos = 0;
			if (pad) {
				if (pad == 1) out--;
				else if (pad == 2) out -= 2;
				break;
			}
		}
	}
	out_len = out - input_buf;

	memcpy(&key_pos, input_buf, sizeof(int));
	out_len -= sizeof(int);
	memcpy(&iv_pos, input_buf + sizeof(int), sizeof(int));
	out_len -= sizeof(int);

	crypto_size = out_len;
	crypto_buf = malloc(crypto_size);
	if (!crypto_buf) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if (get_gen_crypt_part(key_pos, key, sizeof(key)) == NULL
		|| get_gen_crypt_part(iv_pos, iv, sizeof(iv)) == NULL) {
		http_ret = HTTP_INTERNAL;
		goto _exit;
	};

/// AES 256 DEC ///
	EVP_CIPHER_CTX *ctx = NULL;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}

	int len;
	if(1 != EVP_DecryptUpdate(ctx, crypto_buf, &len, input_buf + 2 * sizeof(int), out_len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	out_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, crypto_buf + len, &len)) {
		// ERR_print_errors_fp(stderr);
		http_ret = HTTP_INTERNAL;
		goto _exit;
	}
	out_len += len;

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;
///////////////////

	evbuffer_add(buf,crypto_buf,out_len);

_exit:	
	if (input_buf) free(input_buf);
	if (crypto_buf) free(crypto_buf);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	return http_ret;
} // www_decrypt_handler()
